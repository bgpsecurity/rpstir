#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

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
 * Version 1.0
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
 * This is the garbage collector client, which tracks down all the
 * objects whose state has been changed due to the passage of time
 * and updates its state accordingly.
 **************/

static char *prevTimestamp, *currTimestamp;
static char *theIssuer, *theAKI;   // for passing to callback
static unsigned int theID;         // for passing to callback
static sqlcountfunc countHandler;  // used by countCurrentCRLs
static scmtab *certTable, *crlTable, *roaTable, *manifestTable;

/* callback function for searchscm that records the timestamps */
static int handleTimestamps (scmcon *conp, scmsrcha *s, int numLine)
{
  conp = conp; numLine = numLine;  // silence compiler warnings
  currTimestamp = (char *) s->vec[0].valptr;
  prevTimestamp = (char *) s->vec[1].valptr;
  return 0;
}

/*
 * callback for countCurrentCRLs search; check if count == 0, and
 * if so then do the setting of certs' flags
 */
static int handleIfStale (scmcon *conp, scmsrcha *s, int cnt)
{
  s = s;
  char msg[600];
  if (cnt > 0) return 0;   // exists another crl that is current
  snprintf (msg, 600, "update %s set flags = flags + %d where aki=\"%s\" and issuer=\"%s\"",
	    certTable->tabname, SCM_FLAG_STALECRL, theAKI, theIssuer);
  addFlagTest(msg, SCM_FLAG_STALECRL, 0, 1);
  return statementscm (conp, msg);
}

/*
 * callback for countCurrentCRLs search; check if count > 0, and
 * if so then remove unknown flag from cert
 */
static int handleIfCurrent (scmcon *conp, scmsrcha *s, int cnt)
{
  s = s;
  char msg[128];
  if (cnt == 0) return 0;   // exists another crl that is current
  snprintf (msg, 128, "update %s set flags = flags - %d where local_id=%d",
           certTable->tabname, SCM_FLAG_STALECRL, theID);
  return statementscm (conp, msg);
}

/*
 * callback function for stale crl search that checks stale crls to see if
 * another crl exists that is more recent; if not, it sets all certs
 * covered by this crl to have status stale_crl
 */
static scmsrcha *cntSrch = NULL;

static int countCurrentCRLs (scmcon *conp, scmsrcha *s, int numLine)
{
  numLine = numLine;
  if (cntSrch == NULL) {
    cntSrch = newsrchscm(NULL, 1, 0, 1);
    addcolsrchscm (cntSrch, "local_id", SQL_C_ULONG, 8);
  }
  theIssuer = (char *) s->vec[0].valptr;
  theAKI = (char *) s->vec[1].valptr;
  if (s->nused > 2) {
    theID = *((unsigned int *) s->vec[2].valptr);
  }
  snprintf (cntSrch->wherestr, WHERESTR_SIZE,
	    "issuer=\"%s\" and aki=\"%s\" and next_upd>=\"%s\"",
	    theIssuer, theAKI, currTimestamp);
  return searchscm (conp, crlTable, cntSrch, countHandler, NULL,
                    SCM_SRCH_DOCOUNT);
}

/*
 * callback function for stale manifest search that makes all objects
 * referenced by manifest that is stale
 */
static int handleStaleMan2(scmcon *conp, scmtab *tab, char *files)
{
  char stmt[200];
  snprintf (stmt, sizeof(stmt),
	    "update %s set flags=flags+%d where (flags%%%d)<%d and \"%s\" regexp binary filename;",
	    tab->tabname, SCM_FLAG_STALEMAN,
	    2*SCM_FLAG_STALEMAN, SCM_FLAG_STALEMAN, files);
  return statementscm (conp, stmt);
}

static int handleStaleMan (scmcon *conp, scmsrcha *s, int numLine)
{
  numLine = numLine;
  char *files = (char *)s->vec[0].valptr;
  handleStaleMan2(conp, certTable, files);
  handleStaleMan2(conp, crlTable, files);
  handleStaleMan2(conp, roaTable, files);
  return 0;
}

/*
 * callback function for non-stale manifest search that makes all objects
 * referenced by manifest that is non-stale
 */
static int handleFreshMan2(scmcon *conp, scmtab *tab, char *files)
{
  char stmt[200];
  snprintf (stmt, sizeof(stmt),
	    "update %s set flags=flags-%d where (flags%%%d)>=%d and \"%s\" regexp binary filename;",
	    tab->tabname, SCM_FLAG_STALEMAN,
	    2*SCM_FLAG_STALEMAN, SCM_FLAG_STALEMAN, files);
  return statementscm (conp, stmt);
}

static int handleFreshMan (scmcon *conp, scmsrcha *s, int numLine)
{
  numLine = numLine;
  char *files = (char *)s->vec[0].valptr;
  handleFreshMan2(conp, certTable, files);
  handleFreshMan2(conp, crlTable, files);
  handleFreshMan2(conp, roaTable, files);
  return 0;
}

int main(int argc, char **argv) 
{
  scm      *scmp = NULL;
  scmcon   *connect = NULL;
  scmtab   *metaTable = NULL;
  scmsrcha srch;
  scmsrch  srch1[4];
  char     msg[WHERESTR_SIZE];
  unsigned long blah = 0;
  int      status;

  // initialize
  argc = argc; argv = argv;   // silence compiler warnings
  startSyslog ("garbage");
  (void) setbuf (stdout, NULL);
  scmp = initscm();
  checkErr (scmp == NULL, "Cannot initialize database schema\n");
  connect = connectscm (scmp->dsn, msg, WHERESTR_SIZE);
  checkErr (connect == NULL, "Cannot connect to database: %s\n", msg);
  certTable = findtablescm (scmp, "certificate");
  checkErr (certTable == NULL, "Cannot find table certificate\n");
  crlTable = findtablescm (scmp, "crl");
  checkErr (crlTable == NULL, "Cannot find table crl\n");
  roaTable = findtablescm (scmp, "roa");
  checkErr (roaTable == NULL, "Cannot find table roa\n");
  manifestTable = findtablescm (scmp, "manifest");
  checkErr (manifestTable == NULL, "Cannot find table manifest\n");
  srch.vec = srch1;
  srch.sname = NULL;
  srch.ntot = 4;
  srch.where = NULL;
  srch.context = &blah;

  // find the current time and last time garbage collector ran
  metaTable = findtablescm (scmp, "metadata");
  checkErr (metaTable == NULL, "Cannot find table metadata\n");
  srch.nused = 0;
  srch.vald = 0;
  srch.wherestr = NULL;
  addcolsrchscm (&srch, "current_timestamp", SQL_C_CHAR, 24);
  addcolsrchscm (&srch, "gc_last", SQL_C_CHAR, 24);
  status = searchscm (connect, metaTable, &srch, NULL, handleTimestamps,
                      SCM_SRCH_DOVALUE_ALWAYS);

  // check for expired certs
  certificate_validity (scmp, connect);

  // check for revoked certs
  status = iterate_crl (scmp, connect, model_cfunc);

  // do check for stale crls (next update after last time and before this)
  // if no new crl replaced it (if count = 0 for crls with same issuer and aki
  //   and next update after this), update state of any certs covered by crl
  //   to be unknown
  srch.nused = 0;
  srch.vald = 0;
  snprintf (msg, WHERESTR_SIZE, "next_upd<=\"%s\"", currTimestamp);
  srch.wherestr = msg;
  addcolsrchscm (&srch, "issuer", SQL_C_CHAR, SUBJSIZE);
  addcolsrchscm (&srch, "aki", SQL_C_CHAR, SKISIZE);
  countHandler = handleIfStale;
  status = searchscm (connect, crlTable, &srch, NULL, countCurrentCRLs,
                      SCM_SRCH_DOVALUE_ALWAYS);
  free (srch1[0].valptr);
  free (srch1[1].valptr);

  // now check for stale and then non-stale manifests
  srch.nused = 0;
  srch.vald = 0;
  addcolsrchscm (&srch, "files", SQL_C_CHAR, MANFILES_SIZE);
  status = searchscm (connect, manifestTable, &srch, NULL, handleStaleMan,
                      SCM_SRCH_DOVALUE_ALWAYS);
  snprintf (msg, WHERESTR_SIZE, "next_upd>\"%s\"", currTimestamp);
  status = searchscm (connect, manifestTable, &srch, NULL, handleFreshMan,
                      SCM_SRCH_DOVALUE_ALWAYS);
  free (srch1[0].valptr);

  // check all certs in state unknown to see if now crl with issuer=issuer
  // and aki=ski and nextUpdate after currTime;
  // if so, set state !unknown
  srch.nused = 0;
  srch.vald = 0;
  msg[0] = 0;
  addFlagTest(msg, SCM_FLAG_STALECRL, 1, 0);
  srch.wherestr = msg;
  addcolsrchscm (&srch, "issuer", SQL_C_CHAR, 512);
  addcolsrchscm (&srch, "aki", SQL_C_CHAR, 128);
  addcolsrchscm (&srch, "local_id", SQL_C_ULONG, 8);
  countHandler = handleIfCurrent;
  status = searchscm (connect, certTable, &srch, NULL, countCurrentCRLs,
                      SCM_SRCH_DOVALUE_ALWAYS);
  free (srch1[0].valptr);
  free (srch1[1].valptr);
  free (srch1[2].valptr);

  // write timestamp into database
  snprintf (msg, WHERESTR_SIZE, "update %s set gc_last=\"%s\";",
	    metaTable->tabname, currTimestamp);
  status = statementscm (connect, msg);

  stopSyslog();
  return 0;
}
