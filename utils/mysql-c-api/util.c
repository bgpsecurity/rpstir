#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <my_global.h>
#include <mysql.h>
#include <errmsg.h>

#include "db-internal.h"
#include "logging.h"
#include "util.h"


/*==============================================================================
------------------------------------------------------------------------------*/
int wrap_mysql_stmt_execute(dbconn *conn, MYSQL_STMT *stmt, const char *err_msg_in) {
    int tried = 0;
    int ret = 0;
    uint err_no = 0;

    ret = mysql_stmt_execute(stmt);
    // currently limited to a single reconnect attempt
    while (ret) {
        err_no = mysql_stmt_errno(stmt);
        if (err_no == CR_SERVER_GONE_ERROR  ||  err_no == CR_SERVER_LOST) {  // lost server connection
            LOG(LOG_WARNING, "connection to MySQL server was lost: %s", mysql_stmt_error(stmt));
            if (tried) {
                LOG(LOG_ERR, "not able to reconnect to MySQL server");
                return -1;
            }
            tried++;
            if (reconnectMysqlCApi(&conn)) {
                LOG(LOG_WARNING, "reconnection to MySQL server failed");
                return -1;
            }
            ret = mysql_stmt_execute(stmt);
        } else {  // error, but not server disconnect
            if (err_msg_in != NULL)
                LOG(LOG_ERR, "%s", err_msg_in);
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
            return ret;
        }
    }

    return 0;
}


/*==============================================================================
------------------------------------------------------------------------------*/
int wrap_mysql_query(dbconn *conn, const char *qry, const char *err_msg_in) {
    MYSQL *mysql = conn->mysql;
    int tried = 0;
    int ret = 0;
    uint err_no = 0;

    ret = mysql_query(mysql, qry);
    // currently limited to a single reconnect attempt
    while (ret) {
        err_no = mysql_errno(mysql);
        if (err_no == CR_SERVER_GONE_ERROR  ||  err_no == CR_SERVER_LOST) {  // lost server connection
            LOG(LOG_WARNING, "connection to MySQL server was lost: %s", mysql_error(stmt));
            if (tried) {
                LOG(LOG_ERR, "not able to reconnect to MySQL server");
                return -1;
            }
            tried++;
            if (reconnectMysqlCApi(&conn)) {
                LOG(LOG_WARNING, "reconnection to MySQL server failed");
                return -1;
            }
            ret = mysql_query(mysql, qry);
        } else {  // error, but not server disconnect
            if (err_msg_in != NULL)
                LOG(LOG_ERR, "%s", err_msg_in);
            LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
            return ret;
        }
    }

    return 0;
}


/*==============================================================================
 * @note Caller must free memory returned in first argument.
 * @ret 0 on success, -1 on failure, 1 on NULL value.
------------------------------------------------------------------------------*/
int getStringByFieldname(char **out, MYSQL_RES *result, MYSQL_ROW row, char field_name[]) {
    uint num_fields;
    int field_no = -1;
    uint i = 0;
    MYSQL_FIELD *fields = NULL;
    ulong *lengths = NULL;
    ulong len;

    if (row == NULL) {
        LOG(LOG_ERR, "the argument row is NULL");
        return -1;
    }

    num_fields = mysql_num_fields(result);
    fields = mysql_fetch_fields(result);
    for (i = 0; i < num_fields; i++) {
        if (!strcmp(fields[i].name, field_name)) {
            field_no = i;
            break;
        }
    }
    if (field_no == -1) {
        LOG(LOG_ERR, "could not find field name:  %s", field_name);
        return -1;
    }

    lengths = mysql_fetch_lengths(result);  // mysql allocs the memory
    len = lengths[field_no];

    *out = (char*) malloc(len + 1);
    if (!(*out)) {
        LOG(LOG_ERR, "could not alloc memory");
        return -1;
    }

    memcpy(*out, row[field_no], len);
    (*out)[len] = '\0';

    return 0;
}
