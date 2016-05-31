/**
   Functions to access the database for chaser.
 */

#include "chaser.h"

#include <inttypes.h>
#include <stdio.h>

#include <mysql.h>

#include "db/connect.h"
#include "db/db-internal.h"
#include "util/logging.h"
#include "db/prep-stmt.h"
#include "rpki/db_constants.h"
#include "db/util.h"
#include "util/stringutils.h"

/**=============================================================================
------------------------------------------------------------------------------*/
int db_chaser_read_time(
    dbconn * conn,
    char *curr,
    size_t const curr_len)
{
    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_CHASER][DB_PSTMT_CHASER_GET_TIME];
    int ret;

    if (wrap_mysql_stmt_execute(conn, stmt, "mysql_stmt_execute() failed"))
    {
        return -1;
    }

    // the current timestamp
    MYSQL_TIME curr_ts;
    MYSQL_BIND bind_out[] = {
        {
            .buffer_type = MYSQL_TYPE_TIMESTAMP,
            .buffer = &curr_ts,
        },
    };

    if (mysql_stmt_bind_result(stmt, bind_out))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    if (mysql_stmt_store_result(stmt))
    {
        LOG(LOG_ERR, "mysql_stmt_store_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    if (mysql_stmt_num_rows(stmt) != 1)
    {
        LOG(LOG_ERR, "couldn't read time from db");
        mysql_stmt_free_result(stmt);
        return -1;
    }

    ret = mysql_stmt_fetch(stmt);
    if (ret != 0)
    {
        LOG(LOG_ERR, "mysql_stmt_fetch() failed");
        if (ret == 1)
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
                mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    xsnprintf(curr, curr_len, "%04d-%02d-%02d %02d:%02d:%02d",
              curr_ts.year,
              curr_ts.month,
              curr_ts.day, curr_ts.hour, curr_ts.minute, curr_ts.second);

    mysql_stmt_free_result(stmt);

    return 0;
}

/**=============================================================================
------------------------------------------------------------------------------*/
int64_t db_chaser_read_aia(
    dbconn * conn,
    char ***results,
    int64_t * num_malloced)
{
    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_CHASER][DB_PSTMT_CHASER_GET_AIA];
    unsigned int flag_no_chain = SCM_FLAG_NOCHAIN;
    unsigned int flag_validated = SCM_FLAG_VALIDATED;
    uint64_t num_rows;
    uint64_t num_rows_used = 0;
    int ret;

    MYSQL_BIND bind_in[] = {
        // flag_no_chain
        {
            .buffer_type = MYSQL_TYPE_LONG,
            .buffer = &flag_no_chain,
            .is_unsigned = (my_bool) 1,
            .is_null = (my_bool *) 0,
        },
        {
            .buffer_type = MYSQL_TYPE_LONG,
            .buffer = &flag_no_chain,
            .is_unsigned = (my_bool) 1,
            .is_null = (my_bool *) 0,
        },
        {
            .buffer_type = MYSQL_TYPE_LONG,
            .buffer = &flag_validated,
            .is_unsigned = (my_bool) 1,
            .is_null = (my_bool *) 0,
        },
        {
            .buffer_type = MYSQL_TYPE_LONG,
            .buffer = &flag_validated,
            .is_unsigned = (my_bool) 1,
            .is_null = (my_bool *) 0,
        },
    };

    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        return -1;
    }

    if (wrap_mysql_stmt_execute(conn, stmt, "mysql_stmt_execute() failed"))
    {
        return -1;
    }

    my_bool is_null;
    my_bool is_null_aki;
    ulong length;
    ulong length_aki;
    // the aia.  note: this can be null in the db
    char aia[DB_URI_LEN + 1];   // size of db field plus null terminator
    // the aki.  note: this can be null in the db
    size_t const DB_AKI_LEN = 128;
    char aki[DB_AKI_LEN + 1];   // size of db field plus null terminator
    MYSQL_BIND bind_out[] = {
        {
            .buffer_type = MYSQL_TYPE_VAR_STRING,
            .buffer = aia,
            .buffer_length = sizeof(aia),
            .is_null = &is_null,
            .length = &length,
        },
        {
            .buffer_type = MYSQL_TYPE_VAR_STRING,
            .buffer = aki,
            .buffer_length = sizeof(aki),
            .is_null = &is_null_aki,
            .length = &length_aki,
        },
    };

    if (mysql_stmt_bind_result(stmt, bind_out))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    if (mysql_stmt_store_result(stmt))
    {
        LOG(LOG_ERR, "mysql_stmt_store_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    num_rows = mysql_stmt_num_rows(stmt);
    *num_malloced = num_rows;
    if (num_rows == 0)
    {
        LOG(LOG_DEBUG, "got zero results");
        mysql_stmt_free_result(stmt);
        *results = NULL;
        return 0;
    }

    *results = malloc(num_rows * sizeof(char *));
    if (!(*results))
    {
        LOG(LOG_ERR, "out of memory");
        mysql_stmt_free_result(stmt);
        return ERR_CHASER_OOM;
    }

    uint64_t i;
    char *tmp;
    for (i = 0; i < num_rows; i++)
    {
        ret = mysql_stmt_fetch(stmt);
        if (ret == MYSQL_NO_DATA)
        {
            LOG(LOG_WARNING, "got mysql_no_data");
            continue;
        }
        else if (ret == MYSQL_DATA_TRUNCATED)
        {
            LOG(LOG_WARNING, "got mysql_data_truncated");
            continue;
        }
        else if (ret == 1)
        {
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
                mysql_stmt_error(stmt));
            mysql_stmt_free_result(stmt);
            for (i = 0; i < num_rows_used; i++)
            {
                free((*results)[i]);
            }
            free(*results);
            return -1;
        }
        if (is_null)
        {
            continue;
        }
        else
        {
            tmp = malloc((length + 1) * sizeof(char));
            if (!tmp)
            {
                LOG(LOG_ERR, "out of memory");
                mysql_stmt_free_result(stmt);
                for (i = 0; i < num_rows_used; i++)
                {
                    free((*results)[i]);
                }
                free(*results);
                return ERR_CHASER_OOM;
            }
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
int64_t db_chaser_read_crldp(
    dbconn * conn,
    char ***results,
    int64_t * num_malloced,
    char const *ts,
    int restrict_by_next_update,
    uint32_t seconds)
{
    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_CHASER][DB_PSTMT_CHASER_GET_CRLDP];
    uint64_t num_rows;
    uint64_t num_rows_used = 0;
    int ret;
    int consumed;

    // the interval to add, expressed in seconds
    uint32_t default_seconds = 60 * 60 * 24 * 365 * 100ul;
    // the current timestamp
    MYSQL_TIME curr_ts;
    if (sscanf(ts, "%4u-%2u-%2u %2u:%2u:%2u%n",
               &curr_ts.year,
               &curr_ts.month,
               &curr_ts.day,
               &curr_ts.hour,
               &curr_ts.minute,
               &curr_ts.second,
               &consumed) < 6 || (size_t) consumed < strlen(ts))
    {
        LOG(LOG_ERR, "invalid timestamp: %s", ts);
        return -1;
    }
    curr_ts.neg = (my_bool) 0;
    curr_ts.second_part = (ulong) 0;
    MYSQL_BIND bind_in[] = {
        {
            .buffer_type = MYSQL_TYPE_LONG,
            .buffer = (restrict_by_next_update) ? &seconds : &default_seconds,
            .is_unsigned = (my_bool) 1,
            .is_null = (my_bool *) 0,
        },
        {
            .buffer_type = MYSQL_TYPE_TIMESTAMP,
            .buffer = &curr_ts,
            .is_null = (my_bool *) 0,
        },
    };

    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        return -1;
    }

    if (wrap_mysql_stmt_execute(conn, stmt, "mysql_stmt_execute() failed"))
    {
        return -1;
    }

    my_bool is_null;
    ulong length;
    // the crldp.  note: this can be null in the db
    char crldp[DB_URI_LEN + 1]; // size of db field plus null terminator
    MYSQL_BIND bind_out[] = {
        {
            .buffer_type = MYSQL_TYPE_VAR_STRING,
            .buffer = crldp,
            .buffer_length = sizeof(crldp),
            .is_null = &is_null,
            .length = &length,
        },
    };

    if (mysql_stmt_bind_result(stmt, bind_out))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    if (mysql_stmt_store_result(stmt))
    {
        LOG(LOG_ERR, "mysql_stmt_store_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    num_rows = mysql_stmt_num_rows(stmt);
    *num_malloced = num_rows;
    if (num_rows == 0)
    {
        LOG(LOG_DEBUG, "got zero results");
        mysql_stmt_free_result(stmt);
        *results = NULL;
        return 0;
    }

    *results = malloc(num_rows * sizeof(char *));
    if (!(*results))
    {
        LOG(LOG_ERR, "out of memory");
        mysql_stmt_free_result(stmt);
        return ERR_CHASER_OOM;
    }

    uint64_t i;
    char *tmp;
    for (i = 0; i < num_rows; i++)
    {
        ret = mysql_stmt_fetch(stmt);
        if (ret == MYSQL_NO_DATA)
        {
            LOG(LOG_WARNING, "got mysql_no_data");
            continue;
        }
        else if (ret == MYSQL_DATA_TRUNCATED)
        {
            LOG(LOG_WARNING, "got mysql_data_truncated");
            continue;
        }
        else if (ret == 1)
        {
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
                mysql_stmt_error(stmt));
            mysql_stmt_free_result(stmt);
            for (i = 0; i < num_rows_used; i++)
            {
                free((*results)[i]);
            }
            free(*results);
            return -1;
        }
        if (is_null)
        {
            continue;
        }
        else
        {
            tmp = malloc((length + 1) * sizeof(char));
            if (!tmp)
            {
                LOG(LOG_ERR, "out of memory");
                mysql_stmt_free_result(stmt);
                for (i = 0; i < num_rows_used; i++)
                {
                    free((*results)[i]);
                }
                free(*results);
                return ERR_CHASER_OOM;
            }
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
int64_t db_chaser_read_sia(
    dbconn *conn,
    char ***results,
    int64_t *num_malloced,
    unsigned int chase_not_yet_validated)
{
    MYSQL_STMT *stmt;
    stmt = conn->stmts[DB_CLIENT_TYPE_CHASER][DB_PSTMT_CHASER_GET_SIA];
    uint64_t num_rows;
    uint64_t num_rows_used = 0;
    unsigned int flag;
    int ret;

    if (chase_not_yet_validated)
        flag = 0;
    else
        flag = SCM_FLAG_VALIDATED;
    MYSQL_BIND bind_in[] = {
        // the flag
        {
            .buffer_type = MYSQL_TYPE_LONG,
            .buffer = &flag,
            .is_unsigned = (my_bool)1,
            .is_null = (my_bool *)0,
        },
        // the same flag
        {
            .buffer_type = MYSQL_TYPE_LONG,
            .buffer = &flag,
            .is_unsigned = (my_bool)1,
            .is_null = (my_bool *)0,
        },
    };

    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        return -1;
    }

    if (wrap_mysql_stmt_execute(conn, stmt, "mysql_stmt_execute() failed"))
    {
        return -1;
    }

    my_bool is_null;
    ulong length;
    // the sia.  note: this can be null in the db
    char sia[DB_URI_LEN + 1];   // size of db field plus null terminator
    MYSQL_BIND bind_out[] = {
        {
            .buffer_type = MYSQL_TYPE_VAR_STRING,
            .buffer = sia,
            .buffer_length = sizeof(sia),
            .is_null = &is_null,
            .length = &length,
        },
    };

    if (mysql_stmt_bind_result(stmt, bind_out))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    if (mysql_stmt_store_result(stmt))
    {
        LOG(LOG_ERR, "mysql_stmt_store_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    num_rows = mysql_stmt_num_rows(stmt);
    *num_malloced = num_rows;
    if (num_rows == 0)
    {
        LOG(LOG_DEBUG, "got zero results");
        mysql_stmt_free_result(stmt);
        *results = NULL;
        return 0;
    }

    *results = malloc(num_rows * sizeof(char *));
    if (!(*results))
    {
        LOG(LOG_ERR, "out of memory");
        mysql_stmt_free_result(stmt);
        return ERR_CHASER_OOM;
    }

    uint64_t i;
    char *tmp;
    for (i = 0; i < num_rows; i++)
    {
        ret = mysql_stmt_fetch(stmt);
        if (ret == MYSQL_NO_DATA)
        {
            LOG(LOG_WARNING, "got mysql_no_data");
            continue;
        }
        else if (ret == MYSQL_DATA_TRUNCATED)
        {
            LOG(LOG_WARNING, "got mysql_data_truncated");
            continue;
        }
        else if (ret == 1)
        {
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
                mysql_stmt_error(stmt));
            mysql_stmt_free_result(stmt);
            for (i = 0; i < num_rows_used; i++)
            {
                free((*results)[i]);
            }
            free(*results);
            return -1;
        }
        if (is_null)
        {
            continue;
        }
        else
        {
            tmp = malloc((length + 1) * sizeof(char));
            if (!tmp)
            {
                LOG(LOG_ERR, "out of memory");
                mysql_stmt_free_result(stmt);
                for (i = 0; i < num_rows_used; i++)
                {
                    free((*results)[i]);
                }
                free(*results);
                return ERR_CHASER_OOM;
            }
            memcpy(tmp, sia, length);
            *(tmp + length) = '\0';
            (*results)[num_rows_used] = tmp;
            num_rows_used++;
        }
    }

    mysql_stmt_free_result(stmt);

    return num_rows_used;
}
