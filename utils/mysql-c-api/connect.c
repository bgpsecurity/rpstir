#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <mysql/my_global.h>
#include <mysql/mysql.h>

#include "logutils.h"


/*==============================================================================
------------------------------------------------------------------------------*/
int ch2int(int *out, char in) {
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
            log_msg(LOG_ERR, "expected digit, got '%c' [%s:%u]", in, __FILE__, __LINE__);
        else
            log_msg(LOG_ERR, "expected digit, got '0x%02x' [%s:%u]", (unsigned char)in, __FILE__, __LINE__);
        return(-1);
        break;
    }

    return(0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
int char_arr2uint32_t(uint32_t *out, const char *in, int len) {
    int i;
    int digit;
    uint64_t val = 0;

    if (len > 10) {
        log_msg(LOG_ERR, "input exceeds max length [%s:%u]", __FILE__, __LINE__);
        return(-1);
    }

    for (i = 0; i < len; i++) {
        val *= 10;
        if (ch2int(&digit, in[i])) {
            return (-1);
        }
        val += digit;
    }

    if (val > 0xffffffff) {
        log_msg(LOG_ERR, "value exceeds max size [%s:%u]", __FILE__, __LINE__);
        return(-1);
    }

    *out = (uint32_t) val;

    return(0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
int getLatestSerNum(MYSQL *mysqlp, uint32_t *sn) {
    MYSQL_RES *result;
    MYSQL_ROW row;
    const char qry[] = "select serial_num from rtr_update where create_time="
            "(select max(create_time) from rtr_update)";

    if (mysql_query(mysqlp, qry)) {
        log_msg(LOG_ERR, "could not get latest serial number from db");
        log_msg(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return(-1);
    }

    if ((result = mysql_store_result(mysqlp)) == NULL) {
        log_msg(LOG_ERR, "could not read result set");
        log_msg(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return(-1);
    }

    ulong *lengths;
    ulong sz;
    if (mysql_num_rows(result) == 1) {
        row = mysql_fetch_row(result);
        lengths = mysql_fetch_lengths(result);
        sz = lengths[0];

        if (char_arr2uint32_t(sn, row[0], sz)) {
            log_msg(LOG_ERR, "error converting char[] to uint32_t for serial number");
            return (-1);
        }

        mysql_free_result(result);
        return(0);
    } else if (mysql_num_rows(result) == 0) {
        *sn = (uint32_t)-1;
        mysql_free_result(result);
        return(0);
    } else {
        mysql_free_result(result);
        log_msg(LOG_ERR, "query returned an unexpected number of rows");
        return(-1);
    }
}


/*==============================================================================
 * This function is only for testing.  Someone else is responsible for inserting
 *   records into rtr_update.
------------------------------------------------------------------------------*/
int addNewSerNum(MYSQL *mysqlp, const uint32_t *in) {
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
        log_msg(LOG_ERR, "error reading latest serial number");
        return(-1);
    }

    // Note:  Silently deleting the serial_num I am about to insert.
    // Assumption:  it is no longer needed.
    snprintf(qry, QRY_SZ, "%s%u", "delete from rtr_update where serial_num=",
            new_ser_num);

    if (mysql_query(mysqlp, qry)) {
        log_msg(LOG_ERR, "could not delete serial number %u from db", new_ser_num);
        log_msg(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return(-1);
    }

    if (mysql_affected_rows(mysqlp))
        log_msg(LOG_INFO, "serial_num %u had to be deleted from db before inserting it", new_ser_num);

    snprintf(qry, QRY_SZ, "%s%u %s", "insert into rtr_update values (",
            new_ser_num, ", now())");

    if (mysql_query(mysqlp, qry)) {
        log_msg(LOG_ERR, "could not add new serial number to db");
        log_msg(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return(-1);
    }

    return(0);
}


/*==============================================================================
 * This function is only for testing.  Someone else is responsible for deleting
 *   records from rtr_update.
------------------------------------------------------------------------------*/
int deleteSerNum(MYSQL *mysqlp, uint32_t ser_num) {
    const int QRY_SZ = 1024;
    char qry[QRY_SZ];

    snprintf(qry, QRY_SZ, "%s%u", "delete from rtr_update where serial_num=",
            ser_num);

    printf("query:  %s\n", qry);

    if (mysql_query(mysqlp, qry)) {
        log_msg(LOG_ERR, "could not delete serial number from db");
        log_msg(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return(-1);
    }

    return(0);
}


/*==============================================================================
 * This function is only for testing.  Someone else is responsible for deleting
 *   records from rtr_update.
------------------------------------------------------------------------------*/
int deleteAllSerNums(MYSQL *mysqlp) {
    const char qry[] = "delete from rtr_update";

    if (mysql_query(mysqlp, qry)) {
        log_msg(LOG_ERR, "could not delete all serial numbers from db");
        log_msg(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return(-1);
    }

    return(0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
int connectMysqlCApi(MYSQL *mysqlp,
        const char *host,
        const char *user,
        const char *pass,
        const char *db) {

    if (!mysql_init(mysqlp)) {
        log_msg(LOG_ERR, "insufficient memory to alloc MYSQL object");
        log_msg(LOG_ERR, "    %u: %s", mysql_errno(mysqlp), mysql_error(mysqlp));
        return(-1);
    }

    if (!mysql_real_connect(mysqlp, host, user, pass, db, 0, NULL, 0) ) {
        log_msg(LOG_ERR, "could not connect to MySQL db");
        log_msg(LOG_ERR, "    %u: %s", mysql_errno(mysqlp), mysql_error(mysqlp));
        return(-1);
    }

    return(0);
}
