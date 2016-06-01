#include "util.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mysql.h>
#include <errmsg.h>

#include "config/config.h"
#include "rpki/db_constants.h"

#include "db-internal.h"
#include "util/logging.h"


/*==============================================================================
------------------------------------------------------------------------------*/
int wrap_mysql_stmt_execute(
    dbconn *conn,
    MYSQL_STMT *stmt,
    const char *err_msg_in)
{
    int tried = 0;
    int ret = 0;
    unsigned int err_no = 0;

    ret = mysql_stmt_execute(stmt);
    // currently limited to a single reconnect attempt
    while (ret)
    {
        err_no = mysql_stmt_errno(stmt);
        if (err_no == CR_SERVER_GONE_ERROR || err_no == CR_SERVER_LOST)
        {                       // lost server connection
            LOG(LOG_WARNING, "connection to MySQL server was lost: %s",
                mysql_stmt_error(stmt));
            if (tried)
            {
                LOG(LOG_ERR, "not able to reconnect to MySQL server");
                return -1;
            }
            tried++;
            if (reconnectMysqlCApi(&conn))
            {
                LOG(LOG_WARNING, "reconnection to MySQL server failed");
                return -1;
            }
            ret = mysql_stmt_execute(stmt);
        }
        else
        {                       // error, but not server disconnect
            if (err_msg_in != NULL)
                LOG(LOG_ERR, "%s", err_msg_in);
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
                mysql_stmt_error(stmt));
            return ret;
        }
    }

    return 0;
}


/*==============================================================================
 * @note Caller must free memory returned in first argument.
 * @ret 0 on success, -1 on failure, 1 on NULL value.
------------------------------------------------------------------------------*/
int getStringByFieldname(
    char **out,
    MYSQL_RES *result,
    MYSQL_ROW row,
    char field_name[])
{
    unsigned int num_fields;
    int field_no = -1;
    unsigned int i = 0;
    MYSQL_FIELD *fields = NULL;
    ulong *lengths = NULL;
    ulong len;

    if (row == NULL)
    {
        LOG(LOG_ERR, "the argument row is NULL");
        return -1;
    }

    num_fields = mysql_num_fields(result);
    fields = mysql_fetch_fields(result);
    for (i = 0; i < num_fields; i++)
    {
        if (!strcmp(fields[i].name, field_name))
        {
            field_no = i;
            break;
        }
    }
    if (field_no == -1)
    {
        LOG(LOG_ERR, "could not find field name:  %s", field_name);
        return -1;
    }

    lengths = mysql_fetch_lengths(result);      // mysql allocs the memory
    len = lengths[field_no];

    *out = (char *)malloc(len + 1);
    if (!(*out))
    {
        LOG(LOG_ERR, "could not alloc memory");
        return -1;
    }

    memcpy(*out, row[field_no], len);
    (*out)[len] = '\0';

    return 0;
}

void flag_tests_empty(
    struct flag_tests *tests)
{
    tests->mask = 0;
    tests->result = 0;
}

void flag_tests_default(
    struct flag_tests *tests)
{
    // NOTE: This must be kept in sync with addQueryFlagTests.

    flag_tests_empty(tests);

    flag_tests_add_tests_by_mask(tests, SCM_FLAG_VALIDATED, true);

    if (!CONFIG_RPKI_ALLOW_STALE_VALIDATION_CHAIN_get())
    {
        flag_tests_add_tests_by_mask(tests, SCM_FLAG_NOCHAIN, false);
    }

    if (!CONFIG_RPKI_ALLOW_STALE_CRL_get())
    {
        flag_tests_add_tests_by_mask(tests, SCM_FLAG_STALECRL, false);
    }

    if (!CONFIG_RPKI_ALLOW_STALE_MANIFEST_get())
    {
        flag_tests_add_tests_by_mask(tests, SCM_FLAG_STALEMAN, false);
    }

    if (!CONFIG_RPKI_ALLOW_NO_MANIFEST_get())
    {
        flag_tests_add_tests_by_mask(tests, SCM_FLAG_ONMAN, true);
    }

    if (!CONFIG_RPKI_ALLOW_NOT_YET_get())
    {
        flag_tests_add_tests_by_mask(tests, SCM_FLAG_NOTYET, false);
    }
}

void flag_tests_add_test_by_index(
    struct flag_tests *tests,
    uint_fast16_t flag,
    bool isset)
{
    flag_tests_add_tests_by_mask(
        tests,
        1ULL << flag,
        isset);
}

void flag_tests_add_tests_by_mask(
    struct flag_tests *tests,
    unsigned long long mask,
    bool isset)
{
    tests->mask |= mask;

    if (isset)
    {
        tests->result |= mask;
    }
    else
    {
        tests->result &= ~mask;
    }
}

void flag_tests_bind(
    MYSQL_BIND *parameters,
    struct flag_tests const *tests)
{
    parameters[0] = (MYSQL_BIND){
        .buffer_type = MYSQL_TYPE_LONGLONG,
        .buffer = (void *)&tests->mask,
        .is_unsigned = (my_bool)1,
        .is_null = (my_bool *)0,
    };

    parameters[1] = (MYSQL_BIND){
        .buffer_type = MYSQL_TYPE_LONGLONG,
        .buffer = (void *)&tests->result,
        .is_unsigned = (my_bool)1,
        .is_null = (my_bool *)0,
    };
}
