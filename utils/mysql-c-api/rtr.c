/**
	Functions used for accessing the RTR database.
*/

#include "logging.h"
#include "rtr.h"




/*==============================================================================
------------------------------------------------------------------------------*/
static int startSerialQuery(MYSQL *mysqlp, void **query_state, serial_number_t serial) {


    return (0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
ssize_t serialQueryGetNext(MYSQL *mysql, void * query_state, size_t num_rows,
        PDU ** pdus, bool * is_done) {


    return (0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
void stopSerialQuery(MYSQL *mysql, void * query_state) {
    return;
}


/*==============================================================================
------------------------------------------------------------------------------*/
int getCacheNonce(void *connp, cache_nonce_t *nonce) {
    return getCacheNone((MYSQL*) connp, nonce);
}


/*==============================================================================
------------------------------------------------------------------------------*/
int getLatestSerialNumber(void *connp, serial_number_t *serial) {
    return getLatestSerialNumber((MYSQL*) connp, serial);
}


struct query_state {
    uint32_t ser_num;  // ser_num from which rows should be taken
    uint64_t first_row;  // first row to send
};


/*==============================================================================
------------------------------------------------------------------------------*/
int startSerialQuery(void *connp, void ** query_state, serial_number_t serial) {
    MYSQL *mysql;

    // recs = get all records after serial
    // if (recs == 0)
    //     return 0
    //     send End of Data PDU
    //     send empty query_state

    int QRY_SZ = 256;
    char qry[QRY_SZ];
    snprintf(qry, QRY_SZ, "select asn, ip_addr, is_announce from rtr_incremental "
            "where serial_num=%u order by asn then by ip_addr", serial);

    return (0);
}


/*==============================================================================
 * Assumption:  all rows in rtr_incremental related to a single serial number
 *     are added atomically.
------------------------------------------------------------------------------*/
ssize_t serialQueryGetNext(void *connp, void * query_state, size_t num_rows,
        PDU ** pdus, bool * is_done) {
    return serialQueryGetNext((MYSQL*) connp, query_state, num_rows, pdus, is_done);
}


/*==============================================================================
------------------------------------------------------------------------------*/
void stopSerialQuery(void *connp, void * query_state) {
    return stopSerialQuery((MYSQL*) connp, query_state);
}


/*==============================================================================
------------------------------------------------------------------------------*/
int startResetQuery(void *connp, void ** query_state) {
    return startResetQuery((MYSQL*) connp, query_state);
}


/*==============================================================================
------------------------------------------------------------------------------*/
ssize_t resetQueryGetNext(void *connp, void * query_state, size_t num_rows,
        PDU ** pdus, bool * is_done) {

    return (0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
void stopResetQuery(void *connp, void * query_state) {

    return;
}
