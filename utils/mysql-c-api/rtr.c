/**
	Functions used for accessing the RTR database.
*/

#include <my_global.h>
#include <mysql.h>

#include "logging.h"
#include "rtr.h"
#include "util.h"


struct query_state {
    uint32_t ser_num;  // ser_num to search for first row to send
    uint first_row;    // first row to send.  zero-based
    int bad_ser_num;   // neither the given ser_num, nor its successor, exist
    int data_sent;
    int no_new_data;   // the given ser_num exists, but its successor does not
    int not_ready;     // no valid ser_nums exist, yet
};
//struct _query_state {
//    uint32_t ser_num;  // ser_num to search for first row to send
//    uint64_t first_row;  // first row to send.  zero-based
//};


/*==============================================================================
------------------------------------------------------------------------------*/
void free_query_state(void *qs) {
    if (qs)
        free (qs);
    qs = NULL;
}


/*==============================================================================
------------------------------------------------------------------------------*/
int getCacheNonce(void *connp, cache_nonce_t *nonce) {
    MYSQL *mysqlp = (MYSQL*) connp;
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
            mysql_free_result(result);
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
 * @pre Each timestamp in rtr_update occurs in exactly 1 row.
 * @param[out] serial A return parameter for the serial number.
 * @return 0 if latest is found, -1 on error, 1 if no serial number found.
------------------------------------------------------------------------------*/
int getLatestSerialNumber(void *connp, serial_number_t *serial) {
    MYSQL *mysqlp = (MYSQL*) connp;
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
    uint num_rows = mysql_num_rows(result);
    if (num_rows == 1) {
        row = mysql_fetch_row(result);
        lengths = mysql_fetch_lengths(result);  // mysql allocs the memory

        if (charp2uint32_t(serial, row[0], lengths[0])) {
            LOG(LOG_ERR, "error converting char[] to uint32_t for serial number");
            mysql_free_result(result);
            return (-1);
        }

        mysql_free_result(result);
        return (0);
    } else if (num_rows == 0) {
        mysql_free_result(result);
        return (1);
    } else {
        mysql_free_result(result);
        LOG(LOG_ERR, "returned %u rows for query:  %s", num_rows, qry);
        return (-1);
    }
}


/*==============================================================================
 * @pre serial_num is the first field in the results.
------------------------------------------------------------------------------*/
int resultHasSerNum(MYSQL_RES *result, uint16_t sn) {
    MYSQL_ROW row;
    uint16_t num = 0;
    my_ulonglong num_rows = mysql_num_rows(result);
    ulong *lengths = 0;
    uint i;

    mysql_data_seek(result, 0);
    for (i = 0; i < num_rows; i++) {
        row = mysql_fetch_row(result);
        lengths = mysql_fetch_lengths(result);
        if (lengths == NULL) {
            LOG(LOG_ERR, "should never get here.  check mysql api for mysql_fetch_lengths");
        }
        if (charp2uint16_t(&num, row[0], lengths[0])) {
            LOG(LOG_ERR, "could not convert field to number");
            return (-1);
        }
        if (num == sn)
            return (1);
    }

    return (0);
}


/*==============================================================================
 * Precondition:  All rows in rtr_update are valid.
------------------------------------------------------------------------------*/
int startSerialQuery(void *connp, void **query_state, serial_number_t serial) {
    MYSQL *mysqlp = (MYSQL*) connp;
    MYSQL_RES *result;
    int num_rows = 0;
    struct query_state *state;
    uint16_t new_ser_num = 0;

    if (serial != UINT32_MAX)  // TODO: fix this
        new_ser_num = serial + 1;
    else
        new_ser_num = 0;

    char qry[] = "select serial_num, create_time from rtr_update";
    if (mysql_query(mysqlp, qry)) {
        LOG(LOG_ERR, "could not read rtr_update from db");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    if ((result = mysql_store_result(mysqlp)) == NULL) {
        LOG(LOG_ERR, "could not read result set");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    state = calloc(1, sizeof(struct query_state));
    if (!state) {
        LOG(LOG_ERR, "could not alloc for query_state");
        mysql_free_result(result);
        return (-1);
    }
    state->ser_num = 0;
    state->first_row = 0;
    state->bad_ser_num = 0;
    state->data_sent = 0;
    state->no_new_data = 0;
    state->not_ready = 0;
    *query_state = (void*) state;

    num_rows = mysql_num_rows(result);
    if (num_rows == 0) {
        state->not_ready = 1;
        mysql_free_result(result);
        return (0);
    }

    int ret = resultHasSerNum(result, new_ser_num);
    if (ret == 1) {
        state->ser_num = new_ser_num;
    } else if (ret == -1) {
        mysql_free_result(result);
        return (-1);
    } else {
        ret = resultHasSerNum(result, serial);
        if (ret == 1) {
            state->no_new_data = 1;
        } else if (ret == -1) {
            mysql_free_result(result);
            return (-1);
        } else {
            state->bad_ser_num = 1;
        }
    }

    mysql_free_result(result);

    return (0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
int fillPdu(MYSQL_ROW *row, PDU *pdu) {
    (void) row;  // to avoid -Wunused-parameter  TODO: remove this

    // set protocolVersion
    pdu->protocolVersion = RTR_PROTOCOL_VERSION;

    // set pduType {PDU_IPV4_PREFIX | PDU_IPV6_PREFIX}

    // set cacheNonce

    // set ipxPrefixData

    return (0);
}


/*==============================================================================
 * If there's an error, I call pdu_free_array(); otherwise, the caller does.
------------------------------------------------------------------------------*/
ssize_t serialQueryGetNext(void *connp, void *query_state, size_t max_rows,
        PDU **_pdus, bool *is_done) {
    MYSQL *mysqlp = (MYSQL*) connp;
    MYSQL_RES *result;
    int num_rows = 0;
    size_t unsent_rows = 0;
    size_t num_pdus = 0;
    PDU *pdus;
    int QRY_SZ = 256;
    char qry[QRY_SZ];
    struct query_state *state = (struct query_state*) query_state;

    if (max_rows < 2) {
        LOG(LOG_ERR, "max_rows too small");
        *is_done = 1;
        return (-1);
    }

    if (state->not_ready) {
        LOG(LOG_INFO, "it appears that no data is available to send to routers");
        // TODO: send Error-Report-PDU:2:No-Data-Avail
        *is_done = 1;
        return (1);
    }


    snprintf(qry, QRY_SZ, "select asn, ip_addr, is_announce from rtr_incremental "
            "where serial_num=%" PRIu16 " order by asn, ip_addr", state->ser_num);
    printf("query:  %s\n", qry);

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

    num_rows = mysql_num_rows(result);
    unsent_rows = num_rows - (state->first_row + 1);
    if (unsent_rows >= max_rows)
        num_pdus = max_rows;
    else
        num_pdus = unsent_rows + 1;

    pdus = calloc(num_pdus, sizeof(PDU));
    if (!pdus) {
        LOG(LOG_ERR, "could not alloc for array of PDU");
        mysql_free_result(result);
        return (-1);
    }

    size_t i;
    for (i = 0; i < num_pdus; i++) {

    }

    // TODO: set query_state
    *is_done = true;  // TODO: set this
    *_pdus = pdus;
    mysql_free_result(result);
    return (0);  // TODO: set this

/*
if (max_rows < 2)
    complain

if (query_state.not-ready)
    return Error-Report:No-Data-Avail

if (query_state.bad-sn)
    return Cache-Reset

if (query_state.no-new-data)
    return Cache-Response and End-of-Data

if (!query_state.data_sent)
    append Cache-Response
    set query_state.data_sent
    ++num_pdus

result = query rtr_incremental

current_row = query_state.first_row
last_row = result.num_rows - 1

if (current_row <= last_row)
    mysql_data_seek(current_row);  // goes to zero-based row index

while (current_row <= last_row  &&  num_pdus < max_pdus)
    make pdu from current_row
    num_pdus++
    current_row++

if (max-pdus)
    update query_state to sn, current_row
    return pdus
else  // if we got here, current_row > last_row
    if (sn still valid)
        if (sn+1 is valid)
            update query_state to sn+1, 0
            return pdus
        else
            append End-of-Data
            set is_done
            return pdus
    else
        scrap pdus
        return Error-Report:No-Data-Avail
*/
}


/*==============================================================================
------------------------------------------------------------------------------*/
void stopSerialQuery(void *connp, void * query_state) {
    (void) connp;  // to avoid -Wunused-parameter
    free_query_state(query_state);

    return;
}


/*==============================================================================
------------------------------------------------------------------------------*/
int startResetQuery(void *connp, void ** query_state) {
    MYSQL *mysqlp = (MYSQL*) connp;

    (void) mysqlp;  // to avoid -Wunused-parameter  TODO: remove this
    (void) query_state;  // to avoid -Wunused-parameter  TODO: remove this

    return (0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
ssize_t resetQueryGetNext(void *connp, void * query_state, size_t max_rows,
        PDU ** pdus, bool * is_done) {
    MYSQL *mysqlp = (MYSQL*) connp;
    (void) mysqlp;  // to trick -Wunused-parameter
    (void) query_state;  // to avoid -Wunused-parameter  TODO: remove this
    (void) max_rows;  // to avoid -Wunused-parameter  TODO: remove this
    (void) pdus;  // to avoid -Wunused-parameter  TODO: remove this
    (void) is_done;  // to avoid -Wunused-parameter  TODO: remove this

    // Note: all IPvXPrefix PDUs must be announce (not withdrawal).

    return (0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
void stopResetQuery(void *connp, void * query_state) {
    (void) connp;  // to trick -Wunused-parameter
    free_query_state(query_state);

    return;
}


/*==============================================================================
 * not currently an API function.  currently for testing
 * Precondition:  table rtr_nonce has exactly 0 or 1 rows.
 * TODO: If this becomes used beyond testing, check that old_nonce != new_nonce.
------------------------------------------------------------------------------*/
int setCacheNonce(void *connp, uint16_t nonce) {
    MYSQL *mysqlp = (MYSQL*) connp;
    const char qry_delete[] = "delete from rtr_nonce";
    const int QRY_SZ = 256;
    char qry_insert[QRY_SZ];

    if (mysql_query(mysqlp, qry_delete)) {
        LOG(LOG_ERR, "query failed:  %s", qry_delete);
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    snprintf(qry_insert, QRY_SZ, "insert into rtr_nonce (cache_nonce) "
            "value (%u)", nonce);

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
    } else if (getLatestSerialNumber(connp, &latest_ser_num) == 0) {
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
    snprintf(qry, QRY_SZ, "delete from rtr_update where serial_num=%u",
            new_ser_num);

    if (mysql_query(mysqlp, qry)) {
        LOG(LOG_ERR, "could not delete serial number %u from db", new_ser_num);
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    if (mysql_affected_rows(mysqlp))
        LOG(LOG_INFO, "serial_num %u had to be deleted from db before inserting it", new_ser_num);

    snprintf(qry, QRY_SZ, "insert into rtr_update values (%u, now())",
            new_ser_num);

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

    snprintf(qry, QRY_SZ, "delete from rtr_update where serial_num=%u",
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
