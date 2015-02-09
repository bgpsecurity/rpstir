#include <my_global.h>
#include <mysql.h>

#include "connect.h"
#include "db-internal.h"
#include "util/logging.h"
#include "prep-stmt.h"
#include "util.h"


// Note: keep in sync with enum client_types and each enum prep_stmts_X
static const char *_queries_rtr[] = {
    // DB_PSTMT_RTR_GET_SESSION
    "select session_id from rtr_session limit ?",

    // DB_PSTMT_RTR_GET_LATEST_SERNUM
    "select serial_num from rtr_update order by create_time desc limit 1",

    // DB_PSTMT_RTR_HAS_ROWS_RTR_UPDATE
    "select count(*) > 0 from rtr_update",

    // DB_PSTMT_RTR_READ_SER_NUM_AS_PREV
    "select serial_num " " from rtr_update " " where prev_serial_num=?",

    // DB_PSTMT_RTR_READ_SER_NUM_AS_CURRENT
    "select prev_serial_num, has_full "
        " from rtr_update " " where serial_num=?",

    // DB_PSTMT_RTR_SERIAL_QRY_GET_NEXT
    "select asn, prefix, prefix_length, prefix_max_length, is_announce "
    " from rtr_incremental "
    " where serial_num=? "
    "  and (? or (asn, prefix, prefix_length, prefix_max_length) > (?, ?, ?, ?)) "
    " order by asn, prefix, prefix_length, prefix_max_length "
    " limit ?",

    // DB_PSTMT_RTR_RESET_QRY_GET_NEXT
    "select asn, prefix, prefix_length, prefix_max_length "
    " from rtr_full "
    " where serial_num=? "
    "  and (? or (asn, prefix, prefix_length, prefix_max_length) > (?, ?, ?, ?)) "
    " order by asn, prefix, prefix_length, prefix_max_length "
    " limit ?",

    // DB_PSTMT_RTR_COUNT_SESSION
    "select count(*) from rtr_session",

    // DB_PSTMT_RTR_DELETE_INCOMPLETE_INCREMENTAL
    "delete rtr_incremental "
    "from rtr_incremental "
    "left join rtr_update on "
    "    rtr_incremental.serial_num = rtr_update.serial_num "
    "where rtr_update.serial_num is null",

    // DB_PSTMT_RTR_DELETE_INCOMPLETE_FULL
    "delete rtr_full "
    "from rtr_full "
    "left join rtr_update on "
    "    rtr_full.serial_num = rtr_update.serial_num "
    "where rtr_update.serial_num is null",

    // DB_PSTMT_RTR_DETECT_INCONSISTENT_STATE
    "select count(*) > 0 "
    "from rtr_update "
    "where "
    "    serial_num = ? or "
    "    prev_serial_num = ? or "
    "    prev_serial_num = ?",

    // DB_PSTMT_RTR_INSERT_FULL
    "insert ignore into rtr_full "
    "(serial_num, asn, prefix, prefix_length, prefix_max_length) "
    "select "
    "    ?, "
    "    rpki_roa.asn, "
    "    rpki_roa_prefix.prefix, "
    "    rpki_roa_prefix.prefix_length, "
    "    rpki_roa_prefix.prefix_max_length "
    "from rpki_roa "
    "join rpki_roa_prefix on "
    "    rpki_roa_prefix.roa_local_id = rpki_roa.local_id "
    "where " FLAG_TESTS_EXPRESSION("rpki_roa.flags"),

    // DB_PSTMT_RTR_INSERT_INCREMENTAL
    "insert into rtr_incremental "
    "(serial_num, is_announce, asn, prefix, prefix_length, prefix_max_length) "
    "select ?, ?, t1.asn, t1.prefix, t1.prefix_length, t1.prefix_max_length "
    "from rtr_full as t1 "
    "left join rtr_full as t2 on "
    "    t2.serial_num = ? and "
    "    t2.asn = t1.asn and "
    "    t2.prefix = t1.prefix and "
    "    t2.prefix_length = t1.prefix_length and "
    "    t2.prefix_max_length = t1.prefix_max_length "
    "where t1.serial_num = ? and t2.serial_num is null",

    // DB_PSTMT_RTR_HAS_CHANGES
    "select count(*) > 0 from rtr_incremental where serial_num = ?",

    // DB_PSTMT_RTR_INSERT_UPDATE
    "insert into rtr_update "
    "(serial_num, prev_serial_num, create_time, has_full) "
    "values (?, ?, now(), true)",

    // DB_PSTMT_RTR_DELETE_USELESS_FULL
    "delete from rtr_full where serial_num = ?",

    // DB_PSTMT_RTR_IGNORE_OLD_FULL
    "update rtr_update "
    "set has_full = false "
    "where serial_num <> ? and serial_num <> ?",

    // DB_PSTMT_RTR_DELETE_OLD_FULL
    "delete from rtr_full "
    "where serial_num <> ? and serial_num <> ?",

    // DB_PSTMT_RTR_DELETE_OLD_UPDATE
    "delete from rtr_update "
    "where "
    "    create_time < adddate(now(), interval (-1 * ?) hour) and "
    "    serial_num <> ? and serial_num <> ?",

    // DB_PSTMT_RTR_IGNORE_OLD_INCREMENTAL
    "update rtr_update as r1 "
    "left join rtr_update as r2 on "
    "    r2.serial_num = r1.prev_serial_num "
    "set r1.prev_serial_num = null "
    "where r2.serial_num is null",

    // DB_PSTMT_RTR_DELETE_OLD_INCREMENTAL
    "delete rtr_incremental "
    "from rtr_incremental "
    "left join rtr_update on "
    "    rtr_incremental.serial_num = rtr_update.serial_num "
    "where rtr_update.prev_serial_num is null",

    NULL
};


static const char *_queries_chaser[] = {
    // DB_PSTMT_CHASER_GET_TIME
    "select now() from rpki_metadata",

    // DB_PSTMT_CHASER_GET_CRLDP
    "select crldp from rpki_cert left join rpki_crl "
        " on rpki_cert.aki = rpki_crl.aki "
        " where rpki_crl.next_upd < TIMESTAMPADD(SECOND, ?, ?)",

    // DB_PSTMT_CHASER_GET_SIA
    "select sia from rpki_cert " " where flags & ? = ?",        // either
                                                                // SCM_FLAG_VALIDATED,
                                                                // or 0

    // DB_PSTMT_CHASER_GET_AIA
    "select aia, aki from rpki_cert " " where flags & ? = ? "   // SCM_FLAG_NOCHAIN
        " and flags & ? <> ? "  // ! SCM_FLAG_VALIDATED
        " and aki not in " " (select ski from rpki_cert)",

    NULL
};


static const char **queries[] = {
    _queries_rtr,
    _queries_chaser
};


/**=============================================================================
------------------------------------------------------------------------------*/
void stmtDeleteAll(
    dbconn * conn)
{
    int client_type,
        qry_num;

    for (client_type = 0; client_type < DB_CLIENT_NUM_TYPES; ++client_type)
    {
        if (conn->stmts[client_type] != NULL)
        {
            for (qry_num = 0; queries[client_type][qry_num] != NULL; ++qry_num)
            {
                if (conn->stmts[client_type][qry_num] != NULL)
                {
                    mysql_stmt_close(conn->stmts[client_type][qry_num]);
                    conn->stmts[client_type][qry_num] = NULL;
                }
            }
            free(conn->stmts[client_type]);
            conn->stmts[client_type] = NULL;
        }
    }
}


/**=============================================================================
 * @ret 0 on success, -1 on error.
------------------------------------------------------------------------------*/
static int stmtAdd(
    dbconn * conn,
    int client_type,
    int qry_num)
{
    MYSQL *mysql = conn->mysql;
    const char *qry = queries[client_type][qry_num];
    MYSQL_STMT *stmt;

    stmt = conn->stmts[client_type][qry_num] = mysql_stmt_init(mysql);
    if (stmt == NULL)
    {
        LOG(LOG_ERR, "could not alloc for prepared statement");
        return -1;
    }

    if (mysql_stmt_prepare(stmt, qry, strlen(qry)))
    {
        LOG(LOG_ERR, "error preparing statement");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        conn->stmts[client_type][qry_num] = NULL;
        return -1;
    }

    return 0;
}


/**=============================================================================
------------------------------------------------------------------------------*/
int stmtAddAll(
    dbconn * conn)
{
    int client_type,
        qry_num;

    // initialize to NULL so stmtDeleteAll can be called below
    for (client_type = 0; client_type < DB_CLIENT_NUM_TYPES; ++client_type)
    {
        conn->stmts[client_type] = NULL;
    }

    for (client_type = 0; client_type < DB_CLIENT_NUM_TYPES; ++client_type)
    {
        if (!((1 << client_type) & conn->client_flags))
            continue;

        // find number of queries
        for (qry_num = 0; queries[client_type][qry_num] != NULL; ++qry_num)
        {
        }

        conn->stmts[client_type] = calloc(qry_num, sizeof(MYSQL_STMT *));
        if (conn->stmts[client_type] == NULL)
        {
            LOG(LOG_ERR, "could not alloc array of statement handles");
            stmtDeleteAll(conn);
            return -1;
        }

        for (qry_num = 0; queries[client_type][qry_num] != NULL; ++qry_num)
        {
            if (stmtAdd(conn, client_type, qry_num) != 0)
            {
                LOG(LOG_ERR, "could not prepare a statement");
                stmtDeleteAll(conn);
                return -1;
            }
        }
    }

    return 0;
}
