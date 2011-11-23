#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <my_global.h>
#include <mysql.h>

#include "logging.h"


/*==============================================================================
------------------------------------------------------------------------------*/
static int ch2int(int *out, char in) {
    switch (in) {
    case '0':
        *out = 0;
        break;
    case '1':
        *out = 1;
        break;
    case '2':
        *out = 2;
        break;
    case '3':
        *out = 3;
        break;
    case '4':
        *out = 4;
        break;
    case '5':
        *out = 5;
        break;
    case '6':
        *out = 6;
        break;
    case '7':
        *out = 7;
        break;
    case '8':
        *out = 8;
        break;
    case '9':
        *out = 9;
        break;
    default:
        if (isprint(in))
            LOG(LOG_ERR, "expected digit, got '%c'", in);
        else
            LOG(LOG_ERR, "expected digit, got '0x%02x'", (unsigned char)in);
        return (-1);
        break;
    }

    return (0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
static int charp2uint32_t(uint32_t *out, const char *in, int len) {
    const int MAX_LEN = 10;  // decimal digits for type
    char terminated_input[MAX_LEN + 1];
    uint64_t tmp_out = 0;

    if (len > MAX_LEN) {
        LOG(LOG_ERR, "input exceeds max length");
        return (-1);
    }

    int i = 0;
    for (i = 0; i < len; i++) {
        if (isdigit(in[i])) {
            terminated_input[i] = in[i];
        } else {
            LOG(LOG_ERR, "input char was not a digit");
            return (-1);
        }
    }
    terminated_input[i] = '\0';

    int ret = 0;
    ret = sscanf(terminated_input, "%" SCNu64, &tmp_out);
    if (ret == 0) {
        LOG(LOG_ERR, "no sscanf conversion done");
        return (-1);
    } else if (ret < 0) {
        LOG(LOG_ERR, "sscanf error %d", ret);
        return (-1);
    }

    if (tmp_out > UINT32_MAX) {
        LOG(LOG_ERR, "input exceeds max value");
        return (-1);
    } else
        *out = (uint32_t) tmp_out;

    return (0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
static int charp2uint16_t(uint16_t *out, const char *in, int len) {
    const int MAX_LEN = 5;  // decimal digits for type
    char terminated_input[MAX_LEN + 1];
    uint32_t tmp_out = 0;

    if (len > MAX_LEN) {
        LOG(LOG_ERR, "input exceeds max length");
        return (-1);
    }

    int i = 0;
    for (i = 0; i < len; i++) {
        if (isdigit(in[i])) {
            terminated_input[i] = in[i];
        } else {
            LOG(LOG_ERR, "input char was not a digit");
            return (-1);
        }
    }
    terminated_input[i] = '\0';

    int ret = 0;
    ret = sscanf(terminated_input, "%" SCNu32, &tmp_out);
    if (ret == 0) {
        LOG(LOG_ERR, "no sscanf conversion done");
        return (-1);
    } else if (ret < 0) {
        LOG(LOG_ERR, "sscanf error %d", ret);
        return (-1);
    }

    if (tmp_out > UINT16_MAX) {
        LOG(LOG_ERR, "input exceeds max value");
        return (-1);
    } else
        *out = (uint16_t) tmp_out;

    return (0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
static int char_arr2uint32_t(uint32_t *out, const char *in, int len) {
    int i;
    int digit = 0;
    uint64_t val = 0;

    if (len > 10) {
        LOG(LOG_ERR, "input exceeds max length");
        return (-1);
    }

    for (i = 0; i < len; i++) {
        val *= 10;
        if (ch2int(&digit, in[i])) {
            return (-1);
        }
        val += digit;
    }

    if (val > 0xffffffff) {
        LOG(LOG_ERR, "value exceeds max size");
        return (-1);
    }

    *out = (uint32_t) val;

    return (0);
}


/*==============================================================================
 * not an API function
------------------------------------------------------------------------------*/
int getCacheNonce(MYSQL *mysqlp, uint16_t *nonce) {
    MYSQL_RES *result;
    MYSQL_ROW row;
    const char qry[] = "select cache_nonce from rtr_nonce";

    if (mysql_query(mysqlp, qry)) {
        LOG(LOG_ERR, "could not get cache nonce from db");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    if ((result = mysql_store_result(mysqlp)) == NULL) {
        LOG(LOG_ERR, "could not read result set");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    ulong *lengths;
    ulong sz;
    uint num_rows = mysql_num_rows(result);
    if (num_rows == 1) {
        row = mysql_fetch_row(result);
        lengths = mysql_fetch_lengths(result);
        sz = lengths[0];

        if (charp2uint16_t(nonce, row[0], sz)) {
            LOG(LOG_ERR, "error converting char[] to uint16_t for cache nonce");
            return (-1);
        }

        mysql_free_result(result);
        return (0);
    } else {
        mysql_free_result(result);
        LOG(LOG_ERR, "returned %u rows for query:  %s", num_rows, qry);
        return (-1);
    }
}


/*==============================================================================
 * not currently an API function.  currently for testing
 * Precondition:  table rtr_nonce has exactly 0 or 1 rows.
------------------------------------------------------------------------------*/
int setCacheNonce(MYSQL *mysqlp, uint16_t nonce) {
    const char qry_delete[] = "delete from rtr_nonce";
    const int QRY_SZ = 1024;
    char qry_insert[QRY_SZ];

    if (mysql_query(mysqlp, qry_delete)) {
        LOG(LOG_ERR, "query failed:  %s", qry_delete);
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    snprintf(qry_insert, QRY_SZ, "%s%u)", "insert into rtr_nonce (cache_nonce) "
            "value (", nonce);

    if (mysql_query(mysqlp, qry_insert)) {
        LOG(LOG_ERR, "query failed:  %s", qry_insert);
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    int rows;
    if ((rows = mysql_affected_rows(mysqlp)) != 1) {
        LOG(LOG_ERR, "failed to insert db.rtr_nonce.cache_nonce=%u", nonce);
        LOG(LOG_ERR, "affected rows = %d", rows);
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    return (0);
}


/*==============================================================================
 * not an API function
 * Precondition:  if rtr_update contains any rows, then the latest timestamp
 *     occurs in exactly 1 row.
------------------------------------------------------------------------------*/
int getLatestSerNum(MYSQL *mysqlp, uint32_t *sn) {
    MYSQL_RES *result;
    MYSQL_ROW row;
    const char qry[] = "select serial_num from rtr_update where create_time="
            "(select max(create_time) from rtr_update)";

    if (mysql_query(mysqlp, qry)) {
        LOG(LOG_ERR, "could not get latest serial number from db");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    if ((result = mysql_store_result(mysqlp)) == NULL) {
        LOG(LOG_ERR, "could not read result set");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    ulong *lengths;
    ulong sz;
    uint num_rows = mysql_num_rows(result);
    if (num_rows == 1) {
        row = mysql_fetch_row(result);
        lengths = mysql_fetch_lengths(result);
        sz = lengths[0];

        if (charp2uint32_t(sn, row[0], sz)) {
            LOG(LOG_ERR, "error converting char[] to uint32_t for serial number");
            return (-1);
        }

        mysql_free_result(result);
        return (0);
    } else if (num_rows == 0) {
        *sn = UINT32_MAX;
        mysql_free_result(result);
        return (0);
    } else {
        mysql_free_result(result);
        LOG(LOG_ERR, "returned %u rows for query:  %s", num_rows, qry);
        return (-1);
    }
}


/*==============================================================================
 * This function is only for testing.  Someone else is responsible for inserting
 *   records into rtr_update.
------------------------------------------------------------------------------*/
int addNewSerNum(void *connp, const uint32_t *in) {
    MYSQL *mysqlp = (MYSQL*) connp;
    uint32_t latest_ser_num = 0;
    uint32_t new_ser_num = 0;
    const int QRY_SZ = 1024;
    char qry[QRY_SZ];

    if (in) {
        new_ser_num = *in;
    } else if (getLatestSerNum(mysqlp, &latest_ser_num) == 0) {
        if (latest_ser_num != 0xffffffff)
            new_ser_num = latest_ser_num + 1;
        else
            new_ser_num = 0;
    } else {
        LOG(LOG_ERR, "error reading latest serial number");
        return (-1);
    }

    // Note:  Silently deleting the serial_num I am about to insert.
    // Assumption:  it is no longer needed.
    snprintf(qry, QRY_SZ, "%s%u", "delete from rtr_update where serial_num=",
            new_ser_num);

    if (mysql_query(mysqlp, qry)) {
        LOG(LOG_ERR, "could not delete serial number %u from db", new_ser_num);
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    if (mysql_affected_rows(mysqlp))
        LOG(LOG_INFO, "serial_num %u had to be deleted from db before inserting it", new_ser_num);

    snprintf(qry, QRY_SZ, "%s%u %s", "insert into rtr_update values (",
            new_ser_num, ", now())");

    if (mysql_query(mysqlp, qry)) {
        LOG(LOG_ERR, "could not add new serial number to db");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    return (0);
}


/*==============================================================================
 * This function is only for testing.  Someone else is responsible for deleting
 *   records from rtr_update.
------------------------------------------------------------------------------*/
int deleteSerNum(void *connp, uint32_t ser_num) {
    MYSQL *mysqlp = (MYSQL*) connp;
    const int QRY_SZ = 1024;
    char qry[QRY_SZ];

    snprintf(qry, QRY_SZ, "%s%u", "delete from rtr_update where serial_num=",
            ser_num);

    if (mysql_query(mysqlp, qry)) {
        LOG(LOG_ERR, "could not delete serial number from db");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    LOG(LOG_DEBUG, "%llu rows affected for '%s'", mysql_affected_rows(mysqlp), qry);

    return (0);
}


/*==============================================================================
 * This function is only for testing.  Someone else is responsible for deleting
 *   records from rtr_update.
------------------------------------------------------------------------------*/
int deleteAllSerNums(void *connp) {
    MYSQL *mysqlp = (MYSQL*) connp;
    const char qry[] = "delete from rtr_update";

    LOG(LOG_ERR, "x");
    if (mysql_query(mysqlp, qry)) {
        LOG(LOG_ERR, "could not delete all serial numbers from db");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    return (0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
static void *connectMysqlCApi(
        const char *host,
        const char *user,
        const char *pass,
        const char *db) {
    MYSQL *mysqlp = NULL;

    mysqlp = (MYSQL*) calloc(1, sizeof(MYSQL));

    if (!mysql_init(mysqlp)) {
        LOG(LOG_ERR, "insufficient memory to alloc MYSQL object");
        LOG(LOG_ERR, "    %u: %s", mysql_errno(mysqlp), mysql_error(mysqlp));
        if (mysqlp) {
            free (mysqlp);
            mysqlp = NULL;
        }
        return (NULL);
    }

    if (!mysql_real_connect(mysqlp, host, user, pass, db, 0, NULL, 0) ) {
        LOG(LOG_ERR, "could not connect to MySQL db");
        LOG(LOG_ERR, "    %u: %s", mysql_errno(mysqlp), mysql_error(mysqlp));
        if (mysqlp) {
            free (mysqlp);
            mysqlp = NULL;
        }
        return (NULL);
    }

    return (mysqlp);
}


/*==============================================================================
------------------------------------------------------------------------------*/
void *connectDb(
        const char *host,
        const char *user,
        const char *pass,
        const char *db) {

    return connectMysqlCApi(host, user, pass, db);
}


/*==============================================================================
------------------------------------------------------------------------------*/
void disconnectDb(void *connp) {
    mysql_close((MYSQL *) connp);
}
