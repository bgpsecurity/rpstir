
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "err.h"

/****************
 * This is the garbage collector client, which tracks down all the
 * objects whose state has been changed due to the passage of time
 * and updates its state accordingly.
 **************/

static char *prevTimestamp, *currTimestamp;
static char *theIssuer, *theAKI;   // for passing to callback
static unsigned int theID;         // for passing to callback
static sqlcountfunc countHandler;  // used by countCurrentCRLs
static scmtab *certTable, *crlTable;

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
  sprintf (msg, "update %s set flags = flags + %d where ski=\"%s\" and issuer=\"%s\" and (flags %% %d) < %d",
           certTable->tabname, SCM_FLAG_UNKNOWN, theAKI, theIssuer,
           2 * SCM_FLAG_UNKNOWN, SCM_FLAG_UNKNOWN);
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
  sprintf (msg, "update %s set flags = flags - %d where local_id=%d",
           certTable->tabname, SCM_FLAG_UNKNOWN, theID);
  return statementscm (conp, msg);
}

/*
 * callback function for stale crl search that checks stale crls to see if
 * another crl exists that is more recent; if not, it sets all certs
 * covered by this crl to have status unknown
 */
static scmsrcha cntSrch;
static scmsrch  cntSrch1[1];
static char cntMsg[600];
static unsigned long cntBlah = 0;
static int cntNeedsInit = 1;

static int countCurrentCRLs (scmcon *conp, scmsrcha *s, int numLine)
{
  numLine = numLine;
  if (cntNeedsInit) {
    cntSrch.vec = NULL;
    cntSrch.sname = NULL;
    cntSrch.where = NULL;
    cntSrch.ntot = 1;
    cntSrch.nused = 0;
    cntSrch.context = &cntBlah;
    cntSrch.wherestr = cntMsg;
    cntSrch.vec = cntSrch1;
    addcolsrchscm (&cntSrch, "local_id", SQL_C_ULONG, 8);
  }
  theIssuer = (char *) s->vec[0].valptr;
  theAKI = (char *) s->vec[1].valptr;
  if (s->nused > 2) {
    theID = *((unsigned int *) s->vec[2].valptr);
  }
  sprintf (cntMsg, "issuer=\"%s\" and aki=\"%s\" and next_upd>=\"%s\"",
           theIssuer, theAKI, currTimestamp);
  return searchscm (conp, crlTable, &cntSrch, countHandler, NULL,
                    SCM_SRCH_DOCOUNT);
}

int main(int argc, char **argv) 
{
  scm      *scmp = NULL;
  scmcon   *connect = NULL;
  scmtab   *metaTable = NULL;
  scmsrcha srch;
  scmsrch  srch1[3];
  char     msg[1024];
  unsigned long blah = 0;
  int      status;

  // initialize
  argc = argc; argv = argv;   // silence compiler warnings
  startSyslog ("garbage");
  (void) setbuf (stdout, NULL);
  scmp = initscm();
  checkErr (scmp == NULL, "Cannot initialize database schema\n");
  connect = connectscm (scmp->dsn, msg, 1024);
  checkErr (connect == NULL, "Cannot connect to database: %s\n", msg);
  certTable = findtablescm (scmp, "certificate");
  checkErr (certTable == NULL, "Cannot find table certificate\n");
  crlTable = findtablescm (scmp, "crl");
  checkErr (crlTable == NULL, "Cannot find table crl\n");
  srch.vec = srch1;
  srch.sname = NULL;
  srch.ntot = 3;
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
  sprintf (msg, "next_upd<=\"%s\"", currTimestamp);
  srch.wherestr = msg;
  addcolsrchscm (&srch, "issuer", SQL_C_CHAR, 512);
  addcolsrchscm (&srch, "aki", SQL_C_CHAR, 128);
  countHandler = handleIfStale;
  status = searchscm (connect, crlTable, &srch, NULL, countCurrentCRLs,
                      SCM_SRCH_DOVALUE_ALWAYS);
  free (srch1[0].valptr);
  free (srch1[1].valptr);

  // check all certs in state unknown to see if now crl with issuer=issuer
  // and aki=ski and nextUpdate after currTime;
  // if so, set state !unknown
  srch.nused = 0;
  srch.vald = 0;
  sprintf (msg, "(flags %% %d) >= %d", 2*SCM_FLAG_UNKNOWN, SCM_FLAG_UNKNOWN);
  srch.wherestr = msg;
  addcolsrchscm (&srch, "issuer", SQL_C_CHAR, 512);
  addcolsrchscm (&srch, "ski", SQL_C_CHAR, 128);
  addcolsrchscm (&srch, "local_id", SQL_C_ULONG, 8);
  countHandler = handleIfCurrent;
  status = searchscm (connect, certTable, &srch, NULL, countCurrentCRLs,
                      SCM_SRCH_DOVALUE_ALWAYS);
  free (srch1[0].valptr);
  free (srch1[1].valptr);
  free (srch1[2].valptr);

  // write timestamp into database
  sprintf (msg, "update %s set gc_last=\"%s\";",
           metaTable->tabname, currTimestamp);
  status = statementscm (connect, msg);

  stopSyslog();
  return 0;
}
