#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "err.h"

/*
  $Id$
*/

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Verison 1.0
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  David Montana
 *
 * ***** END LICENSE BLOCK ***** */

/****************
 * This is the chaser client, which tracks down all the URIs of all the
 * authorities that have signed certs.  It can then inform
 * rsynch of the need to synchronize with any repositories that are
 * required but not yet retrieved.
 **************/

#define NUM_FIELDS 3

static char **uris;
static int maxURIs = 4096;
static int numURIs = 0;
static char *prevTimestamp;
static char *currTimestamp;

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
  int i, low, high;
  char **newURIs;

  // check if legal
  if (strlen (uri) == 0) return -1;
  if (strncmp (uri, "rsync://", 8) != 0) return -1;
  for (i = 8; i < (int)strlen(uri); i++) {
    if (isalnum((int)(uri[i]))) continue;
    if (uri[i] == '/') continue;
    if (uri[i] == '.') continue;
    if (uri[i] == '-') continue;
    if (uri[i] == '_') continue;
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

static int isDirectory (const char *uri)
{
  char *slash, *dot;
  slash = strrchr (uri, '/');
  if (strcmp (slash, "/") == 0) return 1;
  dot = strrchr (uri, '.');
  if (dot == NULL) return 1;
  return slash > dot;
}

/* callback function for searchscm that accumulates the list */
static int handleResults (scmcon *conp, scmsrcha *s, int numLine)
{
  int i;
  conp = conp; numLine = numLine;  // silence compiler warnings
  for (i = 0; i < NUM_FIELDS; i++) {
    addURIIfUnique ((char *) s->vec[i].valptr);
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
  fprintf(stderr, "  -p portno   connect to port number (default=APKI_PORT)\n");
  fprintf(stderr, "  -f filename rsync configuration file to model on\n");
  fprintf(stderr, "  -d dirname  rsync executable directory (default=APKI_ROOT/rsync_aur)\n");
  fprintf(stderr, "  -n          don't execute, just print what would have done\n");
  fprintf(stderr, "  -h          this help listing\n");
  return 1;
}

int main(int argc, char **argv) 
{
  scm      *scmp = NULL;
  scmcon   *connect = NULL;
  scmtab   *table = NULL;
  scmsrcha srch;
  scmsrch  srch1[NUM_FIELDS];
  char     msg[1024];
  unsigned long blah = 0;
  int      i, status, numDirs, ch;
  int      portno = 0;
  int      noExecute = 0;
  char     dirs[50][120], str[180], *str2;
  char     *dir2, dirStr[4000], rsyncStr[500], rsyncStr2[4500];
  char     rsyncDir[200];
  char     *origFile = "rsync_pull_sample.config";
  FILE     *fp, *configFile;

  // initialize
  if (getenv ("APKI_ROOT") != NULL)
    snprintf (rsyncDir, 200, "%s/run_scripts", getenv ("APKI_ROOT"));
  else
    sprintf (rsyncDir, ".");
  if (getenv ("APKI_PORT") != NULL)
    portno = atoi (getenv ("APKI_PORT"));
  startSyslog ("chaser");
  uris = calloc (sizeof (char *), maxURIs);
  (void) setbuf (stdout, NULL);

  // parse the command-line flags
  while ((ch = getopt(argc, argv, "f:p:d:nh")) != -1) {
    switch (ch) {
      case 'f':   /* configuration file */
	origFile = strdup (optarg);
	break;
      case 'p':   /* port number */
	portno = atoi (optarg);
	break;
      case 'd':   /* rsync executable directory */
	snprintf (rsyncDir, 200, optarg);
	break;
      case 'n':   /* no execution */
	noExecute = 1;
	break;
      case 'h':   /* help */
      default:
	return printUsage();
    }
  }

  // read in from rsync config file
  fp = fopen (origFile, "r");
  checkErr (fp == NULL, "Unable to open rsync config file: %s\n", origFile);
  dirs[0][0] = 0;
  rsyncStr[0] = 0;
  while (fgets (msg, 1024, fp) != NULL) {
    sscanf (strtok (strdup (msg), "="), "%s", str);
    if (strcmp (str, "DIRS") == 0) {
      str2 = strtok (strtok (NULL, "\""), " ");
      for (numDirs = 0; numDirs < 50; str2 = strtok (NULL, " ")) {
        if (str2 == NULL) break;
        if (strlen (str2) > 0) {
          strncpy (dirs[numDirs++], str2, 120);
        }
      }
    } else if (strcmp (str, "DOLOAD") != 0) {
      strncat (rsyncStr, msg, 500 - strlen(rsyncStr));
    }
  }
  strncat (rsyncStr, "DOLOAD=yes\n", 11);
  checkErr (dirs[0][0] == 0, "DIRS variable not specified in config file\n");

  // load from current repositories to initialize uris
  // it is good to put these in right away, so that any future addresses
  // that are duplicates or subdirectories are immediately discarded
  for (i = 0; i < numDirs; i++) {
    snprintf (str, 180, "rsync://%s", dirs[i]);
    addURIIfUnique (str);
  }

  // set up query
  scmp = initscm();
  checkErr (scmp == NULL, "Cannot initialize database schema\n");
  connect = connectscm (scmp->dsn, msg, 1024);
  checkErr (connect == NULL, "Cannot connect to database: %s\n", msg);
  srch.vec = srch1;
  srch.sname = NULL;
  srch.ntot = NUM_FIELDS;
  srch.where = NULL;
  srch.wherestr = NULL;
  srch.context = &blah;

  // find the current time and last time chaser ran
  table = findtablescm (scmp, "metadata");
  checkErr (table == NULL, "Cannot find table metadata\n");
  srch.nused = 0;
  srch.vald = 0;
  addcolsrchscm (&srch, "current_timestamp", SQL_C_CHAR, 24);
  addcolsrchscm (&srch, "ch_last", SQL_C_CHAR, 24);
  status = searchscm (connect, table, &srch, NULL, handleTimestamps,
                      SCM_SRCH_DOVALUE_ALWAYS);

  // find all the URI's of AIA's, SIA's and CRLDP's in certs
  table = findtablescm (scmp, "certificate");
  checkErr (table == NULL, "Cannot find table certificate\n");
  srch.nused = 0;
  srch.vald = 0;
  snprintf (msg, 1024, "ts_mod > \"%s\"", prevTimestamp);
  srch.wherestr = msg;
  addcolsrchscm (&srch, "sia", SQL_C_CHAR, 1024);
  addcolsrchscm (&srch, "aia", SQL_C_CHAR, 1024);
  addcolsrchscm (&srch, "crldp", SQL_C_CHAR, 1024);
  status = searchscm (connect, table, &srch, NULL, handleResults,
                      SCM_SRCH_DOVALUE_ALWAYS);
  for (i = 0; i < srch.nused; i++) {
    free (srch1[i].valptr);
  }

  // remove original set from list of addresses
  for (i = 0; i < numDirs; i++) {
    snprintf (str, 180, "rsync://%s", dirs[i]);
    removeURI (str);
  }
  if (numURIs == 0)
    return 0;

  // remove all files from list of addresses and replace with directories
  for (i = 0; i < numURIs; i++) {
    if (! isDirectory (uris[i])) {
      strncpy (msg, uris[i], 1024);
      if (strrchr (msg, '/') != NULL) {
	(strrchr (msg, '/'))[1] = 0;
	i = addURIIfUnique (msg);
      }
    }
  }

  // aggregate those from same system and call rsync and rsync_aur
  dirStr[0] = 0;
  for (i = 0; i < numURIs; i++) {
    dir2 = &uris[i][strlen("rsync://")];
    if (dir2 [strlen (dir2) - 1] == '/')
      dir2 [strlen (dir2) - 1] = 0;
    if (i > 0)
      strncat (dirStr, " ", 4000 - strlen(dirStr));
    strncat (dirStr, dir2, 4000 - strlen(dirStr));
  }
  configFile = fopen ("chaser_rsync.config", "w");
  checkErr (configFile == NULL, "Unable to open file for write\n");
  snprintf (rsyncStr2, 4500, "%sDIRS=\"%s\"\n", rsyncStr, dirStr);
  fputs (rsyncStr2, configFile);
  fclose (configFile);
  snprintf (str, 180, "%s/rsync_pull.sh chaser_rsync.config", rsyncDir);
  if (noExecute)
    printf ("Would have executed: %s\n", str);
  else
    system (str);

  // write timestamp into database
  table = findtablescm (scmp, "metadata");
  snprintf (msg, 1024, "update %s set ch_last=\"%s\";",
	    table->tabname, currTimestamp);
  status = statementscm (connect, msg);

  stopSyslog();
  return 0;
}
