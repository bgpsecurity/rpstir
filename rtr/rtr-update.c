/************************
 * Get the next round of RTR data into the database
 ***********************/

#include "err.h"
#include "scmf.h"
#include "querySupport.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <inttypes.h>
#include <time.h>

// number of hours to retain incremental updates
// should be at least 24 + the maximum time between updates, since need
// to always have not just all those within the last 24 hours but also
// one more beyond these
#define RETENTION_HOURS_DEFAULT 96

static scm *scmp = NULL;
static scmcon *connection = NULL;
static scmsrcha *roaSrch = NULL;
static scmtab *roaTable = NULL;
static scmtab *sessionTable = NULL;
static scmtab *fullTable = NULL;
static scmtab *updateTable = NULL;
static scmsrcha *snSrch = NULL;

// serial number of this and previous update
static uint prevSerialNum,
    currSerialNum,
    lastSerialNum;

static void setupSnQuery(
    scm * scmp)
{
    snSrch = newsrchscm(NULL, 1, 0, 1);
    addcolsrchscm(snSrch, "serial_num", SQL_C_ULONG, 8);
    snSrch->wherestr = NULL;
    updateTable = findtablescm(scmp, "rtr_update");
    if (updateTable == NULL)
        printf("Cannot find table rtr_update\n");
}

/*
 * helper function for getLastSerialNumber 
 */
static int setLastSN(
    scmcon * conp,
    scmsrcha * s,
    int numLine)
{
    (void)conp;
    (void)numLine;
    lastSerialNum = *((uint *) (s->vec[0].valptr));
    return -1;                  // stop after first row
}

/****
 * find the serial number from the most recent update
 ****/
static uint getLastSerialNumber(
    scmcon * connect,
    scm * scmp)
{
    lastSerialNum = 0;
    if (snSrch == NULL)
        setupSnQuery(scmp);
    searchscm(connect, updateTable, snSrch, NULL, setLastSN,
              SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_BREAK_VERR,
              "create_time desc");
    return lastSerialNum;
}

/*****
 * allows overriding of retention time for data via environment variable
 *****/
static int retentionHours(
    )
{
    if (getenv("RTR_RETENTION_HOURS") != NULL)
        return atoi(getenv("RTR_RETENTION_HOURS"));
    return RETENTION_HOURS_DEFAULT;
}


/******
 * callback that writes the data from a ROA into the update table
 *   if the ROA is valid
 *****/
static int writeROAData(
    scmcon * conp,
    scmsrcha * s,
    int numLine)
{
    uint asn = *((uint *) s->vec[0].valptr);
    char *ptr = (char *)s->vec[1].valptr,
        *end;
    char msg[1024];
    int sta;
    conp = conp;
    numLine = numLine;

    if (!checkValidity((char *)s->vec[2].valptr, 0, scmp, connection))
        return -1;
    while ((end = strstr(ptr, ", ")) != NULL)
    {
        end[0] = '\0';
        end[1] = '\0';
        snprintf(msg, sizeof(msg),
                 "insert ignore into %s values (%u, %u, \"%s\");",
                 fullTable->tabname, currSerialNum, asn, ptr);
        sta = statementscm_no_data(connection, msg);
        checkErr(sta < 0, "Can't insert into %s", fullTable->tabname);
        ptr = end + 2;
    }
    if (ptr[0] != '\0')
    {
        snprintf(msg, sizeof(msg),
                 "insert ignore into %s values (%u, %u, \"%s\");",
                 fullTable->tabname, currSerialNum, asn, ptr);
        sta = statementscm_no_data(connection, msg);
        checkErr(sta < 0, "Can't insert into %s", fullTable->tabname);
    }
    return 1;
}


int main(
    int argc,
    char **argv)
{
    char msg[1024];
    int sta;
    uint session_count;
    uint update_count;
    uint update_had_changes;    // whether there are any changes from
                                // prevSerialNum to currSerialNum
    uint dont_proceed;
    int first_time = 0;
    int force_update = 0;

    if (argc < 2 || argc > 3)
    {
        fprintf(stderr,
                "Usage: %s <staleness spec file> [<next serial number>]\n",
                argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr,
                "The next serial number should only be specified in test mode.\n");
        return EXIT_FAILURE;
    }

    // initialize the database connection
    scmp = initscm();
    checkErr(scmp == NULL, "Cannot initialize database schema\n");
    connection = connectscm(scmp->dsn, msg, sizeof(msg));
    checkErr(connection == NULL, "Cannot connect to database: %s\n", msg);

    sessionTable = findtablescm(scmp, "rtr_session");
    checkErr(sessionTable == NULL, "Cannot find table rtr_session\n");

    sta = newhstmt(connection);
    checkErr(!SQLOK(sta), "Can't create a new statement handle\n");
    sta = statementscm(connection, "SELECT COUNT(*) FROM rtr_session;");
    checkErr(sta < 0, "Can't query rtr_session\n");
    sta = getuintscm(connection, &session_count);
    pophstmt(connection);
    checkErr(sta < 0, "Can't get results of querying rtr_session\n");
    if (session_count != 1)
    {
        sta = statementscm_no_data(connection, "TRUNCATE TABLE rtr_session;");
        checkErr(sta < 0, "Can't truncate rtr_session");

        sta = statementscm_no_data(connection, "TRUNCATE TABLE rtr_update;");
        checkErr(sta < 0, "Can't truncate rtr_update");

        sta = statementscm_no_data(connection, "TRUNCATE TABLE rtr_full;");
        checkErr(sta < 0, "Can't truncate rtr_full");

        sta =
            statementscm_no_data(connection,
                                 "TRUNCATE TABLE rtr_incremental;");
        checkErr(sta < 0, "Can't truncate rtr_incremental");

        sta =
            statementscm_no_data(connection,
                                 "INSERT INTO rtr_session (session_id) VALUES (FLOOR(RAND() * (1 << 16)));");
        checkErr(sta < 0, "Can't generate a session id");

        first_time = 1;
    }

    // if there's a session but no updates, treat it as the first time
    if (!first_time)
    {
        sta = newhstmt(connection);
        checkErr(!SQLOK(sta), "Can't create a new statement handle\n");
        sta = statementscm(connection, "SELECT COUNT(*) FROM rtr_update;");
        checkErr(sta < 0, "Can't query rtr_update\n");
        sta = getuintscm(connection, &update_count);
        pophstmt(connection);
        checkErr(sta < 0, "Can't get results of querying rtr_update\n");
        if (update_count <= 0)
            first_time = 1;
    }

    // delete any updates that weren't completed
    sta = statementscm_no_data(connection,
                               "delete rtr_incremental\n"
                               "from rtr_incremental\n"
                               "left join rtr_update on rtr_incremental.serial_num = rtr_update.serial_num\n"
                               "where rtr_update.serial_num is null;");
    checkErr(sta < 0, "Can't remove unfinished entries from rtr_incremental");

    sta = statementscm_no_data(connection,
                               "delete rtr_full\n"
                               "from rtr_full\n"
                               "left join rtr_update on rtr_full.serial_num = rtr_update.serial_num\n"
                               "where rtr_update.serial_num is null;");
    checkErr(sta < 0, "Can't remove unfinished entries from rtr_full");

    // find the last serial number
    if (first_time)
    {
        srandom((unsigned int)time(NULL));
        prevSerialNum = (uint) random();
    }
    else
    {
        prevSerialNum = getLastSerialNumber(connection, scmp);
    }
    if (argc > 2)
    {
        force_update = 1;
        if (sscanf(argv[2], "%" SCNu32, &currSerialNum) != 1)
        {
            fprintf(stderr,
                    "Error: next serial number must be a nonnegative integer\n");
            return EXIT_FAILURE;
        }
    }
    else
    {
        currSerialNum = (prevSerialNum == UINT_MAX) ? 0 : (prevSerialNum + 1);
    }

    if (!first_time)
    {
        // make sure we're not about to overwrite currSerialNum, create a
        // loop,
        // or start a diverging history, even though these should be *really*
        // unlikely
        sta = newhstmt(connection);
        checkErr(!SQLOK(sta), "Can't create a new statement handle\n");
        snprintf(msg, sizeof(msg),
                 "SELECT COUNT(*) > 0 FROM rtr_update WHERE\n"
                 "serial_num = %u OR prev_serial_num = %u OR prev_serial_num = %u;",
                 currSerialNum, currSerialNum, prevSerialNum);
        sta = statementscm(connection, msg);
        checkErr(sta < 0, "Can't query rtr_update for unusual corner cases\n");
        sta = getuintscm(connection, &dont_proceed);
        pophstmt(connection);
        checkErr(sta < 0,
                 "Can't get results of querying rtr_update for unusual corner cases\n");

        if (argc > 2)
        {
            checkErr(dont_proceed,
                     "Error: rtr_update is full or in an unusual state, or the specified next serial number already exists\n");
        }
        else
        {
            checkErr(dont_proceed,
                     "Error: rtr_update table is either full or in an unusual state\n");
        }
    }

    // setup up the query if this is the first time
    // note that the where string is set to only select valid roa's, where
    // the definition of valid is given by the staleness specs
    if (roaSrch == NULL)
    {
        QueryField *field;
        roaSrch = newsrchscm(NULL, 3, 0, 1);
        field = findField("asn");
        addcolsrchscm(roaSrch, "asn", field->sqlType, field->maxSize);
        field = findField("ip_addrs");
        addcolsrchscm(roaSrch, "ip_addrs", field->sqlType, field->maxSize);
        field = findField("ski");
        addcolsrchscm(roaSrch, "ski", field->sqlType, field->maxSize);
        roaSrch->wherestr[0] = 0;
        parseStalenessSpecsFile(argv[1]);
        addQueryFlagTests(roaSrch->wherestr, 0);
        roaTable = findtablescm(scmp, "roa");
        checkErr(roaTable == NULL, "Cannot find table roa\n");
        fullTable = findtablescm(scmp, "rtr_full");
        checkErr(fullTable == NULL, "Cannot find table rtr_full\n");
    }

    // write all the data into the database (done writing "full")
    sta = searchscm(connection, roaTable, roaSrch, NULL,
                    writeROAData, SCM_SRCH_DOVALUE_ALWAYS, NULL);
    checkErr(sta < 0 && sta != ERR_SCM_NODATA, "searchscm for ROAs failed\n");

    if (!first_time)
    {
        char differences_query_fmt[] =
            "INSERT INTO rtr_incremental (serial_num, is_announce, asn, ip_addr)\n"
            "SELECT %u, %d, t1.asn, t1.ip_addr\n"
            "FROM rtr_full AS t1\n"
            "LEFT JOIN rtr_full AS t2 ON t2.serial_num = %u AND t2.asn = t1.asn AND t2.ip_addr = t1.ip_addr\n"
            "WHERE t1.serial_num = %u AND t2.serial_num IS NULL;";

        // announcements
        snprintf(msg, sizeof(msg), differences_query_fmt,
                 currSerialNum, 1, prevSerialNum, currSerialNum);
        sta = statementscm_no_data(connection, msg);
        checkErr(sta < 0,
                 "Can't populate rtr_incremental with announcements from serial number %u to %u",
                 prevSerialNum, currSerialNum);

        // withdrawals
        snprintf(msg, sizeof(msg), differences_query_fmt,
                 currSerialNum, 0, currSerialNum, prevSerialNum);
        sta = statementscm_no_data(connection, msg);
        checkErr(sta < 0,
                 "Can't populate rtr_incremental with withdrawals from serial number %u to %u",
                 prevSerialNum, currSerialNum);
    }

    // write the current serial number and time, making the data available
    if (first_time)
    {
        update_had_changes = 1;

        snprintf(msg, sizeof(msg),
                 "insert into rtr_update values (%u, NULL, now(), true);",
                 currSerialNum);
    }
    else
    {
        sta = newhstmt(connection);
        checkErr(!SQLOK(sta), "Can't create a new statement handle\n");
        snprintf(msg, sizeof(msg),
                 "SELECT COUNT(*) > 0 FROM rtr_incremental WHERE serial_num = %u;",
                 currSerialNum);
        sta = statementscm(connection, msg);
        checkErr(sta < 0,
                 "Can't query rtr_incremental to find out if there are any changes\n");
        sta = getuintscm(connection, &update_had_changes);
        pophstmt(connection);
        checkErr(sta < 0,
                 "Can't get results of querying rtr_incremental to find out if there are any changes\n");

        snprintf(msg, sizeof(msg),
                 "insert into rtr_update values (%u, %u, now(), true);",
                 currSerialNum, prevSerialNum);
    }

    // msg should now contain a statement to make updates available
    if (update_had_changes || force_update)
    {
        sta = statementscm_no_data(connection, msg);
        checkErr(sta < 0, "Can't make updates available");
    }
    else
    {
        fprintf(stderr,
                "Note: data had no changes since the last update, so no update was made.\n");

        snprintf(msg, sizeof(msg),
                 "delete from rtr_full where serial_num = %u;", currSerialNum);
        sta = statementscm_no_data(connection, msg);
        checkErr(sta < 0, "Can't delete duplicate data in rtr_full");

        // there's nothing to delete from rtr_incremental
    }

    // clean up all the data no longer needed
    // save last two full updates so that no problems at transition
    // (with client still receiving data from previous one)
    // 
    // NOTE: The order of these updates and deletes is important.
    // All data must be marked as unusable according to rtr_update
    // before it is deleted from rtr_full or rtr_incremental.
    snprintf(msg, sizeof(msg),
             "update rtr_update set has_full = false where serial_num<>%u and serial_num<>%u;",
             prevSerialNum, currSerialNum);
    sta = statementscm_no_data(connection, msg);
    checkErr(sta < 0, "Can't mark old rtr_full data as no longer available");

    snprintf(msg, sizeof(msg),
             "delete from rtr_full where serial_num<>%u and serial_num<>%u;",
             prevSerialNum, currSerialNum);
    sta = statementscm_no_data(connection, msg);
    checkErr(sta < 0, "Can't delete old rtr_full data");

    snprintf(msg, sizeof(msg),
             "delete from rtr_update\n"
             "where create_time < adddate(now(), interval -%d hour)\n"
             "and serial_num<>%u and serial_num<>%u;",
             retentionHours(), prevSerialNum, currSerialNum);
    sta = statementscm_no_data(connection, msg);
    checkErr(sta < 0, "Can't delete expired update metadata");

    sta = statementscm_no_data(connection,
                               "update rtr_update as r1\n"
                               "left join rtr_update as r2 on r2.serial_num = r1.prev_serial_num\n"
                               "set r1.prev_serial_num = NULL\n"
                               "where r2.serial_num is null;");
    checkErr(sta < 0,
             "Can't mark old rtr_incremental data as no longer available");

    sta = statementscm_no_data(connection,
                               "delete rtr_incremental\n"
                               "from rtr_incremental\n"
                               "left join rtr_update on rtr_incremental.serial_num = rtr_update.serial_num\n"
                               "where rtr_update.prev_serial_num is null;");
    checkErr(sta < 0, "Can't delete old rtr_incremental data");

    return 0;
}
