/**
	Functions access the database for the chaser.
 */

#include <inttypes.h>
#include <stdio.h>

#include <my_global.h>
#include <mysql.h>

#include "connect.h"
#include "db-internal.h"
#include "logging.h"
#include "prep-stmt.h"
#include "client-chaser.h"
#include "util.h"

/**=============================================================================
------------------------------------------------------------------------------*/
int db_chaser_read_time(dbconn *conn,
        char *prev, size_t const prev_len,
        char *curr, size_t const curr_len) {
    MYSQL_STMT *stmt = conn->stmts[DB_CLIENT_TYPE_CHASER][DB_PSTMT_CHASER_GET_TIME];
    int ret;

    if (wrap_mysql_stmt_execute(conn, stmt, "mysql_stmt_execute() failed")) {
        return -1;
    }

    MYSQL_BIND bind[2];
    memset(bind, 0, sizeof(bind));
    // the current timestamp
    MYSQL_TIME curr_ts;
    bind[0].buffer_type = MYSQL_TYPE_TIMESTAMP;
    bind[0].buffer = &curr_ts;
    // the previous timestamp
    MYSQL_TIME prev_ts;
    bind[1].buffer_type = MYSQL_TYPE_TIMESTAMP;
    bind[1].buffer = &prev_ts;

    if (mysql_stmt_bind_result(stmt, bind)) {
        LOG(LOG_ERR, "mysql_stmt_bind_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    if (mysql_stmt_store_result(stmt)) {
        LOG(LOG_ERR, "mysql_stmt_store_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    if (mysql_stmt_num_rows(stmt) != 1) {
        LOG(LOG_ERR, "more or less than one metadata record exists");
        mysql_stmt_free_result(stmt);
        return -1;
    }

    ret = mysql_stmt_fetch(stmt);
    if (ret != 0) {
        LOG(LOG_ERR, "mysql_stmt_fetch() failed");
        if (ret == 1)
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    snprintf(prev, prev_len, "%04d-%02d-%02d %02d:%02d:%02d",
            prev_ts.year,
            prev_ts.month,
            prev_ts.day,
            prev_ts.hour,
            prev_ts.minute,
            prev_ts.second
    );

    snprintf(curr, curr_len, "%04d-%02d-%02d %02d:%02d:%02d",
            curr_ts.year,
            curr_ts.month,
            curr_ts.day,
            curr_ts.hour,
            curr_ts.minute,
            curr_ts.second
    );

    mysql_stmt_free_result(stmt);

    return 0;
}

/**=============================================================================
------------------------------------------------------------------------------*/
int db_chaser_write_time(dbconn *conn, char const *ts) {
    MYSQL_STMT *stmt = conn->stmts[DB_CLIENT_TYPE_CHASER][DB_PSTMT_CHASER_WRITE_TIME];

    MYSQL_BIND bind[1];
    memset(bind, 0, sizeof(bind));
    // the current timestamp
    MYSQL_TIME curr_ts;
    sscanf(ts, "%4u-%2u-%2u %2u:%2u:%2u",
            &curr_ts.year,
            &curr_ts.month,
            &curr_ts.day,
            &curr_ts.hour,
            &curr_ts.minute,
            &curr_ts.second);
    curr_ts.neg = (my_bool) 0;
    curr_ts.second_part = (ulong) 0;
    bind[0].buffer_type = MYSQL_TYPE_TIMESTAMP;
    bind[0].buffer = &curr_ts;
    bind[0].is_null = (my_bool*) 0;

    if (mysql_stmt_bind_param(stmt, bind)) {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        return -1;
    }

    if (wrap_mysql_stmt_execute(conn, stmt, "mysql_stmt_execute() failed to update timestamp")) {
        return -1;
    }

    if (mysql_stmt_affected_rows(stmt) != 1) {
        LOG(LOG_ERR, "could not write timestamp to db");
        mysql_stmt_free_result(stmt);
        return -1;
    }

    return 0;
}

/**=============================================================================
------------------------------------------------------------------------------*/
int64_t db_chaser_read_aia(dbconn *conn, char ***results,
        int64_t *num_malloced, int flag_no_chain, int flag_validated) {
    MYSQL_STMT *stmt = conn->stmts[DB_CLIENT_TYPE_CHASER][DB_PSTMT_CHASER_GET_AIA];
    uint64_t num_rows;
    uint64_t num_rows_used = 0;
    int ret;

    MYSQL_BIND bind_in[4];
    memset(bind_in, 0, sizeof(bind_in));
    // flag_no_chain
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].buffer = &flag_no_chain;
    bind_in[0].is_unsigned = (my_bool) 0;
    bind_in[0].is_null = (my_bool*) 0;
    bind_in[1].buffer_type = MYSQL_TYPE_LONG;
    bind_in[1].buffer = &flag_no_chain;
    bind_in[1].is_unsigned = (my_bool) 0;
    bind_in[1].is_null = (my_bool*) 0;
    bind_in[2].buffer_type = MYSQL_TYPE_LONG;
    bind_in[2].buffer = &flag_validated;
    bind_in[2].is_unsigned = (my_bool) 0;
    bind_in[2].is_null = (my_bool*) 0;
    bind_in[3].buffer_type = MYSQL_TYPE_LONG;
    bind_in[3].buffer = &flag_validated;
    bind_in[3].is_unsigned = (my_bool) 0;
    bind_in[3].is_null = (my_bool*) 0;

    if (mysql_stmt_bind_param(stmt, bind_in)) {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        return -1;
    }

    if (wrap_mysql_stmt_execute(conn, stmt, "mysql_stmt_execute() failed")) {
        return -1;
    }

    MYSQL_BIND bind[2];
    my_bool is_null;
    my_bool is_null_aki;
    ulong length;
    ulong length_aki;
    memset(bind, 0, sizeof(bind));
    // the aia.  note: this can be null in the db
    size_t const DB_AIA_LEN = 1024;
    char aia[DB_AIA_LEN + 2];
    bind[0].buffer_type = MYSQL_TYPE_VAR_STRING;
    bind[0].buffer = aia;
    bind[0].buffer_length = DB_AIA_LEN + 1;
    bind[0].is_null = &is_null;
    bind[0].length = &length;
    // the aki.  note: this can be null in the db
    size_t const DB_AKI_LEN = 128;
    char aki[DB_AKI_LEN + 2];
    bind[0].buffer_type = MYSQL_TYPE_VAR_STRING;
    bind[0].buffer = aki;
    bind[0].buffer_length = DB_AKI_LEN + 1;
    bind[0].is_null = &is_null_aki;
    bind[0].length = &length_aki;

    if (mysql_stmt_bind_result(stmt, bind)) {
        LOG(LOG_ERR, "mysql_stmt_bind_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    if (mysql_stmt_store_result(stmt)) {
        LOG(LOG_ERR, "mysql_stmt_store_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    num_rows = mysql_stmt_num_rows(stmt);
    *num_malloced = num_rows;
    if (num_rows == 0) {
        LOG(LOG_DEBUG, "got zero results");
        mysql_stmt_free_result(stmt);
        return 0;
    }

    *results = malloc(num_rows * sizeof(char *));
    if (!(*results)) {
        LOG(LOG_ERR, "out of memory");
        mysql_stmt_free_result(stmt);
        return -1;
    }

    uint64_t i;
    char *tmp;
    for (i = 0; i < num_rows; i++) {
        ret = mysql_stmt_fetch(stmt);
        if (ret == MYSQL_NO_DATA) {
            LOG(LOG_WARNING, "got mysql_no_data");
            continue;
        } else if (ret == MYSQL_DATA_TRUNCATED) {
            LOG(LOG_WARNING, "got mysql_data_truncated");
            continue;
        } else if (ret == 1) {
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
            mysql_stmt_free_result(stmt);
            for (i = 0; i < num_rows_used; i++) {
                free((*results)[i]);
            }
            free(*results);
            return -1;
        }
        if (is_null) {
            continue;
        } else {
            tmp = malloc((length + 1) * sizeof(char));
            memcpy(tmp, aia, length);
            *(tmp + length) = '\0';
            (*results)[num_rows_used] = tmp;
            num_rows_used++;
        }
    }

    mysql_stmt_free_result(stmt);

    return num_rows_used;
}

/**=============================================================================
------------------------------------------------------------------------------*/
int64_t db_chaser_read_crldp(dbconn *conn, char ***results,
        int64_t *num_malloced, char const *ts) {
    MYSQL_STMT *stmt = conn->stmts[DB_CLIENT_TYPE_CHASER][DB_PSTMT_CHASER_GET_CRLDP];
    uint64_t num_rows;
    uint64_t num_rows_used = 0;
    int ret;

    MYSQL_BIND bind_in[1];
    memset(bind_in, 0, sizeof(bind_in));
    // the current timestamp
    MYSQL_TIME curr_ts;
    sscanf(ts, "%4u-%2u-%2u %2u:%2u:%2u",
            &curr_ts.year,
            &curr_ts.month,
            &curr_ts.day,
            &curr_ts.hour,
            &curr_ts.minute,
            &curr_ts.second);
    curr_ts.neg = (my_bool) 0;
    curr_ts.second_part = (ulong) 0;
    bind_in[0].buffer_type = MYSQL_TYPE_TIMESTAMP;
    bind_in[0].buffer = &curr_ts;
    bind_in[0].is_null = (my_bool*) 0;

    if (mysql_stmt_bind_param(stmt, bind_in)) {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        return -1;
    }

    if (wrap_mysql_stmt_execute(conn, stmt, "mysql_stmt_execute() failed")) {
        return -1;
    }

    MYSQL_BIND bind[1];
    my_bool is_null;
    ulong length;
    memset(bind, 0, sizeof(bind));
    // the crldp.  note: this can be null in the db
    size_t const DB_CRLDP_LEN = 1024;
    char crldp[DB_CRLDP_LEN + 2];
    bind[0].buffer_type = MYSQL_TYPE_VAR_STRING;
    bind[0].buffer = crldp;
    bind[0].buffer_length = DB_CRLDP_LEN + 1;
    bind[0].is_null = &is_null;
    bind[0].length = &length;

    if (mysql_stmt_bind_result(stmt, bind)) {
        LOG(LOG_ERR, "mysql_stmt_bind_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    if (mysql_stmt_store_result(stmt)) {
        LOG(LOG_ERR, "mysql_stmt_store_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    num_rows = mysql_stmt_num_rows(stmt);
    *num_malloced = num_rows;
    if (num_rows == 0) {
        LOG(LOG_DEBUG, "got zero results");
        mysql_stmt_free_result(stmt);
        return 0;
    }

    *results = malloc(num_rows * sizeof(char *));
    if (!(*results)) {
        LOG(LOG_ERR, "out of memory");
        mysql_stmt_free_result(stmt);
        return -1;
    }

    uint64_t i;
    char *tmp;
    for (i = 0; i < num_rows; i++) {
        ret = mysql_stmt_fetch(stmt);
        if (ret == MYSQL_NO_DATA) {
            LOG(LOG_WARNING, "got mysql_no_data");
            continue;
        } else if (ret == MYSQL_DATA_TRUNCATED) {
            LOG(LOG_WARNING, "got mysql_data_truncated");
            continue;
        } else if (ret == 1) {
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
            mysql_stmt_free_result(stmt);
            for (i = 0; i < num_rows_used; i++) {
                free((*results)[i]);
            }
            free(*results);
            return -1;
        }
        if (is_null) {
            continue;
        } else {
            tmp = malloc((length + 1) * sizeof(char));
            memcpy(tmp, crldp, length);
            *(tmp + length) = '\0';
            (*results)[num_rows_used] = tmp;
            num_rows_used++;
        }
    }

    mysql_stmt_free_result(stmt);

    return num_rows_used;
}

/**=============================================================================
------------------------------------------------------------------------------*/
int64_t db_chaser_read_sia(dbconn *conn, char ***results,
        int64_t *num_malloced, int trusted_only, int trusted_flag) {
    MYSQL_STMT *stmt;
    if (trusted_only) {
        stmt = conn->stmts[DB_CLIENT_TYPE_CHASER][DB_PSTMT_CHASER_GET_SIA_TRUSTED_ONLY];
    } else {
        stmt = conn->stmts[DB_CLIENT_TYPE_CHASER][DB_PSTMT_CHASER_GET_SIA];
    }
    uint64_t num_rows;
    uint64_t num_rows_used = 0;
    int ret;

    int flag = trusted_flag;
    MYSQL_BIND bind_in[2];
    memset(bind_in, 0, sizeof(bind_in));
    // the flag
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].buffer = &flag;
    bind_in[0].is_unsigned = (my_bool) 0;
    bind_in[0].is_null = (my_bool*) 0;
    // the trusted_flag
    bind_in[1].buffer_type = MYSQL_TYPE_LONG;
    bind_in[1].buffer = &flag;
    bind_in[1].is_unsigned = (my_bool) 0;
    bind_in[1].is_null = (my_bool*) 0;

    if (trusted_only) {
        if (mysql_stmt_bind_param(stmt, bind_in)) {
            LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
            return -1;
        }
    }

    if (wrap_mysql_stmt_execute(conn, stmt, "mysql_stmt_execute() failed")) {
        return -1;
    }

    MYSQL_BIND bind[1];
    my_bool is_null;
    ulong length;
    memset(bind, 0, sizeof(bind));
    // the sia.  note: this can be null in the db
    size_t const DB_SIA_LEN = 1024;
    char sia[DB_SIA_LEN + 2];
    bind[0].buffer_type = MYSQL_TYPE_VAR_STRING;
    bind[0].buffer = sia;
    bind[0].buffer_length = DB_SIA_LEN + 1;
    bind[0].is_null = &is_null;
    bind[0].length = &length;

    if (mysql_stmt_bind_result(stmt, bind)) {
        LOG(LOG_ERR, "mysql_stmt_bind_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    if (mysql_stmt_store_result(stmt)) {
        LOG(LOG_ERR, "mysql_stmt_store_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    num_rows = mysql_stmt_num_rows(stmt);
    *num_malloced = num_rows;
    if (num_rows == 0) {
        LOG(LOG_DEBUG, "got zero results");
        mysql_stmt_free_result(stmt);
        return 0;
    }

    *results = malloc(num_rows * sizeof(char *));
    if (!(*results)) {
        LOG(LOG_ERR, "out of memory");
        mysql_stmt_free_result(stmt);
        return -1;
    }

    uint64_t i;
    char *tmp;
    for (i = 0; i < num_rows; i++) {
        ret = mysql_stmt_fetch(stmt);
        if (ret == MYSQL_NO_DATA) {
            LOG(LOG_WARNING, "got mysql_no_data");
            continue;
        } else if (ret == MYSQL_DATA_TRUNCATED) {
            LOG(LOG_WARNING, "got mysql_data_truncated");
            continue;
        } else if (ret == 1) {
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
            mysql_stmt_free_result(stmt);
            for (i = 0; i < num_rows_used; i++) {
                free((*results)[i]);
            }
            free(*results);
            return -1;
        }
        if (is_null) {
            continue;
        } else {
            tmp = malloc((length + 1) * sizeof(char));
            memcpy(tmp, sia, length);
            *(tmp + length) = '\0';
            (*results)[num_rows_used] = tmp;
            num_rows_used++;
        }
    }

    mysql_stmt_free_result(stmt);

    return num_rows_used;
}
