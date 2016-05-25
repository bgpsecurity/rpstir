#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <mysql.h>

#include "rpki/scm.h"
#include "rpki/scmf.h"
#include "rpki/sqhl.h"
#include "rpki/err.h"
#include "config/config.h"
#include "util/logging.h"
#include "util/macros.h"
#include "util/stringutils.h"


/****************
 * This is the garbage collector client, which tracks down all the
 * objects whose state has been changed due to the passage of time
 * and updates its state accordingly.
 **************/

/** @bug magic constant */
static char prevTimestamp[24];
/** @bug magic constant */
static char currTimestamp[24];
static char theIssuer[SUBJSIZE];
static char theAKI[SKISIZE];
static unsigned int theID;      // for passing to callback
static sqlcountfunc *countHandler;       // used by countCurrentCRLs
static scmtab *certTable;
static scmtab *crlTable;
static scmtab *gbrTable;
static scmtab *roaTable;
static scmtab *manifestTable;

/**
 * @brief
 *     callback function for searchscm() that records the timestamps
 */
static sqlvaluefunc handleTimestamps;
err_code
handleTimestamps(
    scmcon *conp,
    scmsrcha *s,
    ssize_t numLine)
{
    UNREFERENCED_PARAMETER(conp);
    UNREFERENCED_PARAMETER(s);
    UNREFERENCED_PARAMETER(numLine);
    return 0;
}

/**
 * @brief
 *     callback for countCurrentCRLs() search
 *
 * check if count == 0, and if so then do the setting of certs' flags
 */
static sqlcountfunc handleIfStale;
err_code
handleIfStale(
    scmcon *conp,
    scmsrcha *s,
    ssize_t cnt)
{
    UNREFERENCED_PARAMETER(s);
    /** @bug magic constant */
    char msg[600];
    char escaped_aki[2 * strlen(theAKI) + 1];
    char escaped_issuer[2 * strlen(theIssuer) + 1];
    if (cnt > 0)
        return 0;               // exists another crl that is current
    mysql_escape_string(escaped_aki, theAKI, strlen(theAKI));
    mysql_escape_string(escaped_issuer, theIssuer, strlen(theIssuer));
    xsnprintf(msg, sizeof(msg),
              "update %s set flags = flags + %d where aki=\"%s\" and issuer=\"%s\"",
              certTable->tabname, SCM_FLAG_STALECRL, escaped_aki,
              escaped_issuer);
    addFlagTest(msg, SCM_FLAG_STALECRL, 0, 1);
    addFlagTest(msg, SCM_FLAG_CA, 1, 1);
    xsnprintf(msg + strlen(msg), sizeof(msg) - strlen(msg), ";");
    return statementscm_no_data(conp, msg);
}

/**
 * @brief
 *     callback for countCurrentCRLs() search
 *
 * check if count > 0, and if so then remove unknown flag from cert
 */
static sqlcountfunc handleIfCurrent;
err_code
handleIfCurrent(
    scmcon *conp,
    scmsrcha *s,
    ssize_t cnt)
{
    /** @bug magic constant */
    char msg[128];
    UNREFERENCED_PARAMETER(s);
    if (cnt == 0)
        return 0;               // exists another crl that is current
    xsnprintf(msg, sizeof(msg),
              "update %s set flags = flags - %d where local_id=%d;",
              certTable->tabname, SCM_FLAG_STALECRL, theID);
    return statementscm_no_data(conp, msg);
}

/**
 * @brief
 *     callback function for stale crl search
 *
 * checks stale crls to see if another crl exists that is more recent;
 * if not, it sets all certs covered by this crl to have status
 * stale_crl
 */
static scmsrcha *cntSrch = NULL;

static sqlvaluefunc countCurrentCRLs;
err_code
countCurrentCRLs(
    scmcon *conp,
    scmsrcha *s,
    ssize_t numLine)
{
    UNREFERENCED_PARAMETER(s);
    UNREFERENCED_PARAMETER(numLine);
    if (cntSrch == NULL)
    {
        cntSrch = newsrchscm(NULL, 1, 0, 1);
        /** @bug ignores error code without explanation */
        addcolsrchscm(cntSrch, "local_id", SQL_C_ULONG, 8);
    }
    char escaped_aki[2 * strlen(theAKI) + 1];
    char escaped_issuer[2 * strlen(theIssuer) + 1];
    mysql_escape_string(escaped_aki, theAKI, strlen(theAKI));
    mysql_escape_string(escaped_issuer, theIssuer, strlen(theIssuer));
    xsnprintf(cntSrch->wherestr, WHERESTR_SIZE,
              "issuer=\"%s\" and aki=\"%s\" and next_upd>=\"%s\"",
              escaped_issuer, escaped_aki, currTimestamp);
    return searchscm(conp, crlTable, cntSrch, countHandler, NULL,
                     SCM_SRCH_DOCOUNT, NULL);
}

/**
 * @brief
 *     callback function for stale manifest search
 *
 * marks accordingly all objects referenced by manifest that is stale
 */
static char staleManStmt[MANFILES_SIZE];
/** @bug magic constant */
static char *staleManFiles[10000];
static int numStaleManFiles = 0;

static err_code
handleStaleMan2(
    scmcon *conp,
    scmtab *tab,
    char *files)
{
    char escaped_files[2 * strlen(files) + 1];
    mysql_escape_string(escaped_files, files, strlen(files));
    xsnprintf(staleManStmt, sizeof(staleManStmt),
              "update %s set flags=flags+%d where (flags%%%d)<%d and \"%s\" regexp binary filename;",
              tab->tabname, SCM_FLAG_STALEMAN,
              2 * SCM_FLAG_STALEMAN, SCM_FLAG_STALEMAN, escaped_files);
    return statementscm_no_data(conp, staleManStmt);
}

static sqlvaluefunc handleStaleMan;
err_code
handleStaleMan(
    scmcon *conp,
    scmsrcha *s,
    ssize_t numLine)
{
    UNREFERENCED_PARAMETER(numLine);
    UNREFERENCED_PARAMETER(conp);
    int len = *((unsigned int *)s->vec[1].valptr);
    staleManFiles[numStaleManFiles] = malloc(len + 1);
    memcpy(staleManFiles[numStaleManFiles], (char *)s->vec[0].valptr, len);
    staleManFiles[numStaleManFiles][len] = 0;
    numStaleManFiles++;
    return 0;
}

/*
 * callback function for non-stale manifest search that marks accordingly
 * all objects referenced by manifest that is non-stale
 */
static err_code
handleFreshMan2(
    scmcon *conp,
    scmtab *tab,
    char *files)
{
    char escaped_files[2 * strlen(files) + 1];
    mysql_escape_string(escaped_files, files, strlen(files));
    xsnprintf(staleManStmt, sizeof(staleManStmt),
              "update %s set flags=flags-%d where (flags%%%d)>=%d and \"%s\" regexp binary filename;",
              tab->tabname, SCM_FLAG_STALEMAN,
              2 * SCM_FLAG_STALEMAN, SCM_FLAG_STALEMAN, escaped_files);
    return statementscm_no_data(conp, staleManStmt);
}

int main(
    int argc,
    char **argv)
{
    scm *scmp = NULL;
    scmcon *connect = NULL;
    scmtab *metaTable = NULL;
    char msg[WHERESTR_SIZE];
    err_code status;
    int i;

    // initialize
    (void)argc;
    (void)argv;                // silence compiler warnings
    (void)setbuf(stdout, NULL);
    OPEN_LOG("garbage", LOG_USER);
    if (!my_config_load())
    {
        LOG(LOG_ERR, "can't load configuration");
        exit(EXIT_FAILURE);
    }
    scmp = initscm();
    checkErr(scmp == NULL, "Cannot initialize database schema\n");
    connect = connectscm(scmp->dsn, msg, sizeof(msg));
    checkErr(connect == NULL, "Cannot connect to database: %s\n", msg);
    certTable = findtablescm(scmp, "certificate");
    checkErr(certTable == NULL, "Cannot find table certificate\n");
    crlTable = findtablescm(scmp, "crl");
    checkErr(crlTable == NULL, "Cannot find table crl\n");
    gbrTable = findtablescm(scmp, "ghostbusters");
    checkErr(gbrTable == NULL, "Cannot find table ghostbusters\n");
    roaTable = findtablescm(scmp, "roa");
    checkErr(roaTable == NULL, "Cannot find table roa\n");
    manifestTable = findtablescm(scmp, "manifest");
    checkErr(manifestTable == NULL, "Cannot find table manifest\n");

    scmsrch srch1cols[] = {
        {
            .colno = 1,
            .sqltype = SQL_C_CHAR,
            .colname = "current_timestamp",
            .valptr = currTimestamp,
            .valsize = sizeof(currTimestamp),
            .avalsize = 0,
        },
        {
            .colno = 2,
            .sqltype = SQL_C_CHAR,
            .colname = "gc_last",
            .valptr = prevTimestamp,
            .valsize = sizeof(prevTimestamp),
            .avalsize = 0,
        },
    };
    scmsrcha srch1 = {
        .vec = srch1cols,
        .sname = NULL,
        .ntot = ELTS(srch1cols),
        .nused = ELTS(srch1cols),
        .vald = 0,
        .where = NULL,
        .wherestr = NULL,
    };

    // find the current time and last time garbage collector ran
    metaTable = findtablescm(scmp, "metadata");
    checkErr(metaTable == NULL, "Cannot find table metadata\n");
    status = searchscm(connect, metaTable, &srch1, NULL, &handleTimestamps,
                       SCM_SRCH_DOVALUE_ALWAYS, NULL);
    if (status != 0)
    {
        fprintf(stderr, "Error searching for timestamps: %s\n",
                err2string(status));
        exit(EXIT_FAILURE);
    }

    // check for expired certs
    /** @bug ignores error code without explanation */
    certificate_validity(scmp, connect);

    // check for revoked certs
    status = iterate_crl(scmp, connect, &revoke_cert_by_serial);
    if (status != 0 && status != ERR_SCM_NODATA)
    {
        fprintf(stderr, "Error checking for revoked certificates: %s\n",
                err2string(status));
        exit(EXIT_FAILURE);
    }

    // do check for stale crls (next update after last time and before this)
    // if no new crl replaced it (if count = 0 for crls with same issuer and
    // aki
    // and next update after this), update state of any certs covered by crl
    // to be unknown
    scmsrch srch2cols[] = {
        {
            .colno = 1,
            .sqltype = SQL_C_CHAR,
            .colname = "issuer",
            .valptr = theIssuer,
            .valsize = sizeof(theIssuer),
            .avalsize = 0,
        },
        {
            .colno = 2,
            .sqltype = SQL_C_CHAR,
            .colname = "aki",
            .valptr = theAKI,
            .valsize = sizeof(theAKI),
            .avalsize = 0,
        },
    };
    xsnprintf(msg, sizeof(msg), "next_upd<=\"%s\"", currTimestamp);
    scmsrcha srch2 = {
        .vec = srch2cols,
        .sname = NULL,
        .ntot = ELTS(srch2cols),
        .nused = ELTS(srch2cols),
        .vald = 0,
        .where = NULL,
        .wherestr = msg,
    };
    countHandler = &handleIfStale;
    status = searchscm(connect, crlTable, &srch2, NULL, &countCurrentCRLs,
                       SCM_SRCH_DOVALUE_ALWAYS, NULL);
    if (status != 0 && status != ERR_SCM_NODATA)
    {
        fprintf(stderr, "Error searching for CRLs: %s\n",
                err2string(status));
        exit(EXIT_FAILURE);
    }

    // now check for stale and then non-stale manifests
    // note: by doing non-stale test after stale test, those objects that
    // are referenced by both stale and non-stale manifests, set to not stale
    char files[MANFILES_SIZE];
    unsigned int fileslen;
    scmsrch srch3cols[] = {
        {
            .colno = 1,
            .sqltype = SQL_C_BINARY,
            .colname = "files",
            .valptr = files,
            .valsize = sizeof(files),
            .avalsize = 0,
        },
        {
            .colno = 2,
            .sqltype = SQL_C_ULONG,
            .colname = "fileslen",
            .valptr = &fileslen,
            .valsize = sizeof(fileslen),
            .avalsize = 0,
        },
    };
    scmsrcha srch3 = {
        .vec = srch3cols,
        .sname = NULL,
        .ntot = ELTS(srch3cols),
        .nused = ELTS(srch3cols),
        .vald = 0,
        .where = NULL,
        /** @bug should srch3.wherestr be set to NULL? */
        .wherestr = msg,
    };
    numStaleManFiles = 0;
    status = searchscm(connect, manifestTable, &srch3, NULL, &handleStaleMan,
                       SCM_SRCH_DOVALUE_ALWAYS, NULL);
    if (status != 0 && status != ERR_SCM_NODATA)
    {
        fprintf(stderr, "Error searching for manifests: %s\n",
                err2string(status));
        exit(EXIT_FAILURE);
    }
    for (i = 0; i < numStaleManFiles; i++)
    {
        /** @bug ignores error code without explanation */
        handleStaleMan2(connect, certTable, staleManFiles[i]);
        /** @bug ignores error code without explanation */
        handleStaleMan2(connect, crlTable, staleManFiles[i]);
        /** @bug ignores error code without explanation */
        handleStaleMan2(connect, gbrTable, staleManFiles[i]);
        /** @bug ignores error code without explanation */
        handleStaleMan2(connect, roaTable, staleManFiles[i]);
        free(staleManFiles[i]);
    }
    /**
     * @bug why is this set to 0?  seems like it's just an expensive
     * no-op given that the columns haven't and won't change
     */
    srch3.vald = 0;
    xsnprintf(msg, sizeof(msg), "next_upd>\"%s\"", currTimestamp);
    numStaleManFiles = 0;
    status = searchscm(connect, manifestTable, &srch3, NULL, &handleStaleMan,
                       SCM_SRCH_DOVALUE_ALWAYS, NULL);
    if (status != 0 && status != ERR_SCM_NODATA)
    {
        fprintf(stderr, "Error searching for manifests: %s\n",
                err2string(status));
        exit(EXIT_FAILURE);
    }
    for (i = 0; i < numStaleManFiles; i++)
    {
        /** @bug ignores error code without explanation */
        handleFreshMan2(connect, certTable, staleManFiles[i]);
        /** @bug ignores error code without explanation */
        handleFreshMan2(connect, crlTable, staleManFiles[i]);
        /** @bug ignores error code without explanation */
        handleFreshMan2(connect, gbrTable, staleManFiles[i]);
        /** @bug ignores error code without explanation */
        handleFreshMan2(connect, roaTable, staleManFiles[i]);
        free(staleManFiles[i]);
    }

    // check all certs in state unknown to see if now crl with issuer=issuer
    // and aki=ski and nextUpdate after currTime;
    // if so, set state !unknown
    scmsrch srch4cols[] = {
        {
            .colno = 1,
            .sqltype = SQL_C_CHAR,
            .colname = "issuer",
            .valptr = theIssuer,
            .valsize = sizeof(theIssuer),
            .avalsize = 0,
        },
        {
            .colno = 2,
            .sqltype = SQL_C_CHAR,
            .colname = "aki",
            .valptr = theAKI,
            .valsize = sizeof(theAKI),
            .avalsize = 0,
        },
        {
            .colno = 3,
            .sqltype = SQL_C_ULONG,
            .colname = "local_id",
            .valptr = &theID,
            .valsize = sizeof(theID),
            .avalsize = 0,
        },
    };
    msg[0] = 0;
    addFlagTest(msg, SCM_FLAG_STALECRL, 1, 0);
    scmsrcha srch4 = {
        .vec = srch4cols,
        .sname = NULL,
        .ntot = ELTS(srch4cols),
        .nused = ELTS(srch4cols),
        .vald = 0,
        .where = NULL,
        .wherestr = msg,
    };
    countHandler = &handleIfCurrent;
    status = searchscm(connect, certTable, &srch4, NULL, &countCurrentCRLs,
                       SCM_SRCH_DOVALUE_ALWAYS, NULL);
    if (status != 0 && status != ERR_SCM_NODATA)
    {
        fprintf(stderr, "Error searching for certificates: %s\n",
                err2string(status));
        exit(EXIT_FAILURE);
    }

    // write timestamp into database
    xsnprintf(msg, sizeof(msg), "update %s set gc_last=\"%s\";",
              metaTable->tabname, currTimestamp);
    status = statementscm_no_data(connect, msg);
    if (status != 0)
    {
        fprintf(stderr, "Error updating timestamp: %s\n",
                err2string(status));
        exit(EXIT_FAILURE);
    }

    config_unload();
    CLOSE_LOG();
    return 0;
}
