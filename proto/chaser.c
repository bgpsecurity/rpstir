
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "err.h"

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

static int supersedes (const char *str1, const char *str2)
{
  if (strncmp (str1, str2, strlen (str1)) != 0) return 0;
  if (strlen (str1) == strlen (str2)) return 1;
  if (str1 [strlen(str1) - 1] == '/') return 1;
  if (str2 [strlen(str1)] == '/') return 1;
  return 0;
}

/* update list of uris by adding the next one */
static void addIfUnique (char *uri)
{
  int i, cmp;
  int low = 0;
  int high = numURIs;
  char **newURIs;

  if (strlen (uri) == 0) return;

  // binary search for where new uri belongs
  while (low < high) {
    i = (low + high) / 2;
    cmp = strcmp (uri, uris[i]);
    if (cmp == 0) return;    // if not unique, nothing more to do
    if (cmp < 0) {
      high = i;
    } else {
      low = i + 1;
    }
  }

  // if previous one supersedes it, just return without inserting
  if ((low > 0) && supersedes (uris[low-1], uri))
    return;

  // search for which ones to remove
  while ((high < numURIs) && supersedes (uri, uris[high]))
    high++;

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
}

/* callback function for searchscm that accumulates the list */
static int handleResults (scmcon *conp, scmsrcha *s, int numLine)
{
  int i;
  conp = conp; numLine = numLine;  // silence compiler warnings
  for (i = 0; i < NUM_FIELDS; i++) {
    addIfUnique ((char *) s->vec[i].valptr);
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

int main(int argc, char **argv) 
{
  scm      *scmp = NULL;
  scmcon   *connect = NULL;
  scmtab   *table = NULL;
  scmsrcha srch;
  scmsrch  srch1[NUM_FIELDS];
  char     msg[1024];
  unsigned long blah = 0;
  int      i, status, numDirs;
  char     *filename, sys[120], dirs[50][60], str[180], *str2;
  FILE     *fp;

  // initialize
  argc = argc; argv = argv;   // silence compiler warnings
  startSyslog ("chaser");
  uris = calloc (sizeof (char *), maxURIs);
  (void) setbuf (stdout, NULL);

  // read in from rsync config file
  filename = (argc == 1) ? "rsync_pull_sample.config" : argv[1];
  fp = fopen (filename, "r");
  checkErr (fp == NULL, "Unable to open rsync config file: %s\n", filename);
  sys[0] = 0;
  dirs[0][0] = 0;
  while (fgets (msg, 1024, fp) != NULL) {
    sscanf (strtok (msg, "="), "%s", str);
    if (strcmp (str, "SYSTEM") == 0) {
      sscanf (strtok (NULL, ""), "%s", sys);
    } else if (strcmp (str, "DIRS") == 0) {
      str2 = strtok (strtok (NULL, "\""), " ");
      for (numDirs = 0; numDirs < 50; str2 = strtok (NULL, " ")) {
        if (str2 == NULL) break;
        if (strlen (str2) > 0) {
          strcpy (dirs[numDirs++], str2);
        }
      }
    }
  }
  checkErr (sys[0] == 0, "SYSTEM variable not specified in config file\n");
  checkErr (dirs[0][0] == 0, "DIRS variable not specified in config file\n");

  // load from current repositories to initialize uris
  for (i = 0; i < numDirs; i++) {
    sprintf (str, "rsync://%s/%s", sys, dirs[i]);
    addIfUnique (str);
  }

  // set up query
  scmp = initscm();
  checkErr (scmp == NULL, "Cannot initialize database schema\n");
  connect = connectscm (scmp->dsn, msg, 1024);
  checkErr (connect == NULL, "Cannot connect to %s: %s\n", scmp->dsn, msg);
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
  sprintf (msg, "ts_mod > \"%s\"", prevTimestamp);
  srch.wherestr = msg;
  addcolsrchscm (&srch, "sia", SQL_C_CHAR, 1024);
  addcolsrchscm (&srch, "aia", SQL_C_CHAR, 1024);
  addcolsrchscm (&srch, "crldp", SQL_C_CHAR, 1024);
  status = searchscm (connect, table, &srch, NULL, handleResults,
                      SCM_SRCH_DOVALUE_ALWAYS);
  for (i = 0; i < srch.nused; i++) {
    free (srch1[i].valptr);
  }

  // write timestamp into database
  table = findtablescm (scmp, "metadata");
  sprintf (msg, "update %s set ch_last=\"%s\";",
           table->tabname, currTimestamp);
  status = statementscm (connect, msg);

  for (i = 0; i < numURIs; i++) printf ("uri = %s\n", uris[i]);
  stopSyslog();
  return 0;
}
