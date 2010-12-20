#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "err.h"
#include "logutils.h"

/*
  $Id$
*/

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 3.0-beta
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.  All Rights Reserved.
 *
 * Contributor(s):  David Montana, Brenton Kohler
 *
 * ***** END LICENSE BLOCK ***** */

/****************
 * This is the chaser client, which tracks down all the URIs of all the
 * authorities that have signed certs.  It can then inform
 * rsynch of the need to synchronize with any repositories that are
 * required but not yet retrieved.
 **************/

static char **uris;
static int maxURIs = 4096;
static int numURIs = 0;
static char *prevTimestamp;
static char *currTimestamp;
static int verbose = 0;

/*
 * return true if str2 is a subdirectory of or file in directory str1
 * test is fully based on the name, without any actual checking the dir
 */
static int supersedes (const char *str1, const char *str2)
{
  if (strncmp (str1, str2, strlen (str1)) != 0) return 0;
  if (strlen (str1) == strlen (str2)) return 1;
  if (str1 [strlen(str1) - 1] == '/') return 1;
  if (str2 [strlen(str1)] == '/') return 1;
  return 0;
}

/* binary search for insertion point or existing position */
static int inURIList (char *uri, int *position)
{
  int i, cmp;
  int low = 0;
  int high = numURIs;

  while (low < high) {
    i = (low + high) / 2;
    cmp = strcmp (uri, uris[i]);
    if (cmp == 0) {
      *position = i;
      return 1;
    }
    if (cmp < 0) {
      high = i;
    } else {
      low = i + 1;
    }
  }
  *position = low;
  return 0;
}

/* remove a uri from the list if it's there */
static void removeURI (char *uri)
{
  int pos;
  if (! inURIList (uri, &pos)) return;
  memmove (&uris[pos], &uris[pos+1], (numURIs - pos - 1) * sizeof (char *));
  numURIs--;
}

/* update list of uris by adding the next one */
static int addURIIfUnique (char *uri)
{
  int i, low, high, len;
  char **newURIs;

  // check if legal -- length, starts with rsync, only uses
  // valid characters
  if (uri == NULL || (len = strlen(uri)) == 0) return -1;
  if (strncmp (uri, RSYNC_PREFIX, RSYNC_PREFIX_LEN) != 0) return -1;
  for (i = RSYNC_PREFIX_LEN; i < len; i++) {
    int ch = uri[i];
    if (isalnum(ch) == 0 && strchr("-/._", ch) == NULL)
      return -1;
  }

  // if already there, all done
  if (inURIList (uri, &low)) return low;

  // if previous one supersedes it, just return without inserting
  if ((low > 0) && supersedes (uris[low-1], uri)) return low;

  // search for which ones to remove
  for (high = low; (high < numURIs) && supersedes (uri, uris[high]); high++);

  // do the insert and remove
  // first, free memory of deleted ones
  for (i = low; i < high; i++) {
    free (uris[i]);
  }
  if (high != (low + 1)) {
    // make array bigger if necessary
    if ((low == high) && (numURIs == maxURIs)) {
      newURIs = calloc (sizeof (char *), maxURIs * 2);
      memcpy (newURIs, uris, maxURIs * sizeof (char *));
      free (uris);
      uris = newURIs;
      maxURIs *= 2;
    }
    // move to make space, overwriting deleted ones
    memmove (&uris[low+1], &uris[high], (numURIs - high) * sizeof (char *));
  }
  // finally, add new one in and modify num
  uris[low] = strdup (uri);
  numURIs += 1 + low - high;
  return low;
}

/*****
static int isDirectory (const char *uri)
{
  char *slash, *dot;
  slash = strrchr (uri, '/');
  if (strcmp (slash, "/") == 0) return 1;
  dot = strrchr (uri, '.');
  if (dot == NULL) return 1;
  return slash > dot;
}
********/

// static variables for searching for parent
static scmsrcha parentSrch;
static scmsrch  parentSrch1[1];
static char parentWhere[1024];
static unsigned long parentBlah = 0;
static int parentNeedsInit = 1;
static int parentCount;
static scmtab *theCertTable = NULL;

/* callback function for searchscm that just notes that parent exists */
static int foundIt (scmcon *conp, scmsrcha *s, int numLine)
{
  conp = conp; numLine = numLine;  // silence compiler warnings
  parentCount++;
  return 0;
}

/* callback function for searchscm that accumulates the aia's */
static int handleAIAResults (scmcon *conp, scmsrcha *s, int numLine)
{
  conp = conp; numLine = numLine;  // silence compiler warnings
  if (parentNeedsInit) {
    parentNeedsInit = 0;
    parentSrch.sname = NULL;
    parentSrch.where = NULL;
    parentSrch.ntot = 1;
    parentSrch.nused = 0;
    parentSrch.context = &parentBlah;
    parentSrch.wherestr = parentWhere;
    parentSrch.vec = parentSrch1;
    addcolsrchscm (&parentSrch, "filename", SQL_C_CHAR, FNAMESIZE);
  }
  snprintf(parentWhere, sizeof(parentWhere), "ski=\"%s\"",
	   (char *) s->vec[0].valptr);
  parentCount = 0;
  searchscm(conp, theCertTable, &parentSrch, NULL, foundIt,
	    SCM_SRCH_DOVALUE_ALWAYS, NULL);
  if (parentCount == 0) {
    addURIIfUnique ((char *) s->vec[1].valptr);
    if (verbose)
      log_msg(LOG_DEBUG, "AIA: %s", (char *) s->vec[1].valptr);
  }
  return 0;
}

/* callback function for searchscm that accumulates the crldp's */
/* note that a CRLDP in the cert table can now be a single URI or a set
   of URIs separated by semicolons */

static int handleCRLDPResults (scmcon *conp, scmsrcha *s, int numLine)
{
  char *res;
  char *oneres;

  conp = conp; numLine = numLine;  // silence compiler warnings
  res = (char *)(s->vec[0].valptr);
  oneres = strtok(res, ";");
  while ( oneres != NULL && oneres[0] != 0 )
    {
      addURIIfUnique(oneres);
      log_msg(LOG_DEBUG, "CRLDP: %s", oneres);
      oneres = strtok(NULL, ";");
    }
  return 0;
}

/* callback function for searchscm that accumulates the sia's */
static int handleSIAResults (scmcon *conp, scmsrcha *s, int numLine)
{
  char *res;
  char *oneres;

  conp = conp; numLine = numLine;  // silence compiler warnings
  res = (char *)(s->vec[0].valptr);
  oneres = strtok(res, ";");
  while( oneres != NULL && oneres[0] != 0)
    {
      addURIIfUnique (oneres);
      log_msg(LOG_DEBUG, "SIA: %s", oneres);
      oneres = strtok(NULL, ";");
    }
  return 0;
}

/* callback function for searchscm that records the timestamps */
static int handleTimestamps (scmcon *conp, scmsrcha *s, int numLine)
{
  conp = conp; numLine = numLine;  // silence compiler warnings
  currTimestamp = (char *) s->vec[0].valptr;
  prevTimestamp = (char *) s->vec[1].valptr;
  return 0;
}

static int printUsage()
{
  fprintf(stderr, "Usage:\n"); 
  fprintf(stderr, "  -p portno   connect to port number (default=RPKI_PORT)\n");
  fprintf(stderr, "  -f filename rsync configuration file to model on\n");
  fprintf(stderr, "  -d dirname  rsync executable directory (default=RPKI_ROOT)\n");
  fprintf(stderr, "  -n          don't execute rsync, just print what would have done\n");
  fprintf(stderr, "  -t          run by grabbing only Trust Anchor URIs from the database\n");
  fprintf(stderr, "  -s          chase all SIA values\n");
  fprintf(stderr, "  -v          verbose\n");
  fprintf(stderr, "  -h          this help listing\n");
  return 1;
}

int main(int argc, char **argv) 
{
  scm      *scmp = NULL;
  scmcon   *connect = NULL;
  scmtab   *table = NULL;
  scmsrcha srch;
  scmsrch  srch1[2];
  char     msg[1024];
  unsigned long blah = 0;
  int      i, status, numDirs, ch;
  int      portno = 0;
  int      listPort = 0;
  int      tcount = 0;
  int      noExecute = 0;
  int      taOnly = 0;
  int      chaseSIA = 1;
  char     dirs[50][120], str[180], *str2;
  char     *dir2, dirStr[4000], rsyncStr[500], rsyncStr2[4500];
  char     rsyncDir[200];
  char     *origFile = "rsync_pull_sample.config";
  FILE     *fp, *configFile;

  // initialize
  if (getenv ("RPKI_ROOT") != NULL)
    snprintf (rsyncDir, sizeof(rsyncDir), "%s", getenv ("RPKI_ROOT"));
  else
    sprintf (rsyncDir, ".");
  if (getenv ("RPKI_PORT") != NULL)
    portno = atoi (getenv ("RPKI_PORT"));
  if (getenv ("RPKI_LISTPORT") != NULL)
    listPort = atoi (getenv ("RPKI_LISTPORT"));
  else
    listPort = 3450;
  if (getenv ("RPKI_TCOUNT") != NULL)
    tcount = atoi (getenv ("RPKI_TCOUNT"));
  else
    tcount = 8;
  uris = calloc (sizeof (char *), maxURIs);
  (void) setbuf (stdout, NULL);

  // parse the command-line flags
  while ((ch = getopt(argc, argv, "f:p:d:nthv")) != -1) {
    switch (ch) {
      case 'f':   /* configuration file */
	origFile = strdup (optarg);
	break;
      case 'p':   /* port number */
	portno = atoi (optarg);
	break;
      case 'd':   /* rsync executable directory */
	snprintf (rsyncDir, sizeof(rsyncDir), optarg);
	break;
      case 'n':   /* no execution */
	noExecute = 1;
	break;
      case 't':   /* chase trust anchor SIAs only */
	taOnly = 1;
	break;
      case 'v':   /* verbose */
	verbose = 1;
	break;
      case 'h':   /* help */
      default:
	return printUsage();
    }
  }

  if (log_init("chaser.log", "chaser", LOG_DEBUG, LOG_DEBUG) != 0) {
    perror("Could not initialize chaser log file");
    exit(1);
  }

  // read in from rsync config file
  fp = fopen (origFile, "r");
  checkErr (fp == NULL, "Unable to open rsync config file: %s\n", origFile);
  dirs[0][0] = 0;
  rsyncStr[0] = 0;
  while (fgets (msg, sizeof(msg), fp) != NULL) {
    sscanf (strtok (strdup (msg), "="), "%s", str);
    if (strcmp (str, "DIRS") == 0) {
      str2 = strtok (strtok (NULL, "\""), " ");
      for (numDirs = 0; numDirs < 50; str2 = strtok (NULL, " ")) {
        if (str2 == NULL) break;
        if (strlen (str2) > 0) {
          strncpy (dirs[numDirs++], str2, sizeof(dirs[0]));
        }
      }
    } else if (strcmp (str, "DOLOAD") != 0) {
      strncat (rsyncStr, msg, sizeof(rsyncStr) - strlen(rsyncStr));
    }
  }
  strncat (rsyncStr, "DOLOAD=yes\n", 11);
  checkErr (dirs[0][0] == 0, "DIRS variable not specified in config file\n");

  // load from current repositories to initialize uris
  // it is good to put these in right away, so that any future addresses
  // that are duplicates or subdirectories are immediately discarded
  for (i = 0; i < numDirs; i++) {
    snprintf (str, sizeof(str), RSYNC_PREFIX "%s", dirs[i]);
    addURIIfUnique (str);
    log_msg(LOG_DEBUG, "PRECONFIGURED URI: %s", str);
  }

  // set up query
  scmp = initscm();
  checkErr (scmp == NULL, "Cannot initialize database schema\n");
  connect = connectscm (scmp->dsn, msg, sizeof(msg));
  checkErr (connect == NULL, "Cannot connect to database: %s\n", msg);
  srch.vec = srch1;
  srch.sname = NULL;
  srch.ntot = 2;
  srch.where = NULL;
  srch.wherestr = NULL;
  srch.context = &blah;

  if(!taOnly)
  {
  // find the current time and last time chaser ran
  table = findtablescm (scmp, "metadata");
  checkErr (table == NULL, "Cannot find table metadata\n");
  srch.nused = 0;
  srch.vald = 0;
  addcolsrchscm (&srch, "current_timestamp", SQL_C_CHAR, 24);
  addcolsrchscm (&srch, "ch_last", SQL_C_CHAR, 24);
  status = searchscm (connect, table, &srch, NULL, handleTimestamps,
                      SCM_SRCH_DOVALUE_ALWAYS, NULL);

  // add crldp field if cert either has no crl or crl is out-of-date
  table = findtablescm (scmp, "certificate");
  checkErr (table == NULL, "Cannot find table certificate\n");
  theCertTable = table;
  srch.nused = 0;
  srch.vald = 0;
  snprintf (msg, sizeof(msg),
	    "rpki_crl.filename is null or rpki_crl.next_upd < \"%s\"",
	    currTimestamp);
  srch.wherestr = msg;
  addcolsrchscm (&srch, "crldp", SQL_C_CHAR, SIASIZE);
  status = searchscm (connect, table, &srch, NULL, handleCRLDPResults,
                      SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN_CRL, NULL);
  free (srch1[0].valptr);

  // add aia field if cert has no parent
  srch.nused = 0;
  srch.vald = 0;
  msg[0] = 0;
  addFlagTest(msg, SCM_FLAG_NOCHAIN, 1, 0);
  addcolsrchscm (&srch, "aki", SQL_C_CHAR, SKISIZE);
  addcolsrchscm (&srch, "aia", SQL_C_CHAR, SIASIZE);
  status = searchscm (connect, table, &srch, NULL, handleAIAResults,
                      SCM_SRCH_DOVALUE_ALWAYS, NULL);
  free (srch1[0].valptr);
  free (srch1[1].valptr);

  // add sia field (command line option)
  if (chaseSIA)
    {
      srch.nused = 0;
      srch.vald = 0;
      msg[0] = 0;
      srch.where = NULL;
      srch.wherestr = NULL;
      addcolsrchscm(&srch, "sia", SQL_C_CHAR, SIASIZE);
      status = searchscm (connect, table, &srch, NULL, handleSIAResults,
			  SCM_SRCH_DOVALUE_ALWAYS, NULL);
      if (status != ERR_SCM_NOERR) {
	log_msg(LOG_ERR, "Error chasing SIAs: %s (%d)",
		err2string(status), status);
      }
      free(srch1[0].valptr);
    }
  
  }//this ends the normal operation
  else
  {
	table = findtablescm (scmp, "certificate");
	checkErr (table == NULL, "Cannot find table certificate\n");
	theCertTable = table;
	srch.nused = 0;
	srch.vald = 0;
	snprintf (msg, sizeof(msg),"((flags%%%d)>=%d)",2*SCM_FLAG_TRUSTED, SCM_FLAG_TRUSTED);
	srch.wherestr = msg;
	addcolsrchscm (&srch, "sia", SQL_C_CHAR, SIASIZE);
	status = searchscm (connect, table, &srch, NULL, handleSIAResults,
					SCM_SRCH_DOVALUE_ALWAYS, NULL);
	free (srch1[0].valptr);
  }
  // remove original set from list of addresses
  // This is now commented out under the assumption that the chaser will be the 
  //  only cron'ed event to occur and it will always build it's list of URI's
  //  from what is available in the database and from the static list provided
  //  in the config file. 
  //
  //for (i = 0; i < numDirs; i++) {
  //  snprintf (str, sizeof(str), RSYNC_PREFIX "%s", dirs[i]);
  //  removeURI (str);
  //}
  if (numURIs == 0)
    return 0;

  // remove all files from list of addresses and replace with directories
  /*** actually, don't do this - work with individual files
  for (i = 0; i < numURIs; i++) {
    if (! isDirectory (uris[i])) {
      strncpy (msg, uris[i], sizeof(msg));
      if (strrchr (msg, '/') != NULL) {
	(strrchr (msg, '/'))[1] = 0;
	i = addURIIfUnique (msg);
      }
    }
  }
  ****/

  // aggregate those from same system and call rsync and rsync_aur
  dirStr[0] = 0;
  for (i = 0; i < numURIs; i++) {
    dir2 = &uris[i][RSYNC_PREFIX_LEN];
    if (dir2 [strlen (dir2) - 1] == '/')
      dir2 [strlen (dir2) - 1] = 0;
    if (i > 0)
      strncat (dirStr, " ", sizeof(dirStr) - strlen(dirStr));
    strncat (dirStr, dir2, sizeof(dirStr) - strlen(dirStr));
  }
  configFile = fopen ("chaser_rsync.config", "w");
  checkErr (configFile == NULL, "Unable to open file for write\n");
  snprintf (rsyncStr2, sizeof(rsyncStr2), "%sDIRS=\"%s\"\n", rsyncStr, dirStr);
  fputs (rsyncStr2, configFile);
  fclose (configFile);
  snprintf(str, sizeof(str), "python %s/rsync_aur/rsync_cord.py -c chaser_rsync.config -t %d -p %d", rsyncDir, tcount, listPort);
  if (noExecute)
    log_msg(LOG_NOTICE, "Would have executed: %s", str);
  else
    // NOTE: THE system CALL IS INHERENTLY DANGEROUS.
    //   CARE WAS TAKEN TO ENSURE THAT THE ARGUMENT str DOES NOT
    //   CONTAIN FUNNY SHELL CHARACTERS
    system (str);

  // write timestamp into database
  table = findtablescm (scmp, "metadata");
  snprintf (msg, sizeof(msg), "update %s set ch_last=\"%s\";",
	    table->tabname, currTimestamp);
  status = statementscm (connect, msg);

  log_close();
  return 0;
}
