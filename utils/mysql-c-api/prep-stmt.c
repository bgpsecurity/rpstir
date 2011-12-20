#include <my_global.h>
#include <mysql.h>

#include "connect.h"
#include "db-internal.h"
#include "logging.h"
#include "prep-stmt.h"
#include "rtr.h"
#include "util.h"


// Note:  keep in sync with enum client_types and each enum prep_stmts_X
static const char * _queries_rtr[] = {
    "select session_id from rtr_session",

    "select serial_num from rtr_update order by create_time desc limit 1",

    "select asn, ip_addr, is_announce "
    " from rtr_incremental "
    " where serial_num=? "
    " order by asn, ip_addr "
    " limit ?, ?",

    NULL
};
static const char * * queries[] = {
    _queries_rtr
};


/**=============================================================================
------------------------------------------------------------------------------*/
void stmtDeleteAll(dbconn *conn) {
    int client_type, qry_num;

    for (client_type = 0; client_type < DB_CLIENT_NUM_TYPES; ++client_type) {
        if (conn->stmts[client_type] != NULL) {
            for (qry_num = 0; queries[client_type][qry_num] != NULL; ++qry_num) {
                if (conn->stmts[client_type][qry_num] != NULL) {
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
static int stmtAdd(dbconn *conn,
        int client_type,
        int qry_num) {
    MYSQL *mysql = conn->mysql;
    const char *qry = queries[client_type][qry_num];

    conn->stmts[client_type][qry_num] = mysql_stmt_init(mysql);
    if (conn->stmts[client_type][qry_num] == NULL) {
        LOG(LOG_ERR, "could not alloc for prepared statement");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
        return -1;
    }

    if (mysql_stmt_prepare(conn->stmts[client_type][qry_num], qry, strlen(qry))) {
        LOG(LOG_ERR, "error preparing statement");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
        mysql_stmt_close(conn->stmts[client_type][qry_num]);
        conn->stmts[client_type][qry_num] = NULL;
        return -1;
    }

    return 0;
}


/**=============================================================================
------------------------------------------------------------------------------*/
int stmtAddAll(dbconn *conn) {
    int client_type, qry_num;

    // initialize to NULL so stmtDeleteAll can be called below
    for (client_type = 0; client_type < DB_CLIENT_NUM_TYPES; ++client_type) {
        conn->stmts[client_type] = NULL;
    }

    for (client_type = 0; client_type < DB_CLIENT_NUM_TYPES; ++client_type) {
        if (!((1 << client_type) & conn->client_flags))
            continue;

        // find number of queries
        for (qry_num = 0; queries[client_type][qry_num] != NULL; ++qry_num) {}

        conn->stmts[client_type] = malloc(sizeof(MYSQL_STMT *) * qry_num);
        if (conn->stmts[client_type] == NULL) {
            LOG(LOG_ERR, "coult not alloc array of statement handles");
            stmtDeleteAll(conn);
            return -1;
        }

        for (qry_num = 0; queries[client_type][qry_num] != NULL; ++qry_num) {
            if (stmtAdd(conn, client_type, qry_num) != 0) {
                LOG(LOG_ERR, "coult not prepare a statement");
                stmtDeleteAll(conn);
                return -1;
            }
        }
    }

    return 0;
}
