/**
	Functions used for accessing the RTR database.
*/

#include <arpa/inet.h>
#include <bits/socket.h>

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
 * @pre serial_num is the first field in the rtr_update.
 * @ret 1 if serial number is found in rtr_update, -1 on error, 0 if serial
 *      number is not found, -2 if no rows are found.
------------------------------------------------------------------------------*/
int isValidSerNum(MYSQL *connp, uint32_t sn) {
    MYSQL *mysqlp = (MYSQL*) connp;
    MYSQL_RES *result;
    MYSQL_ROW row;
    uint32_t num = 0;
    my_ulonglong num_rows = 0;
    ulong *lengths = 0;
    uint i;

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

    num_rows = mysql_num_rows(result);
    if (num_rows == 0) {
        LOG(LOG_INFO, "rtr_update is empty");
        mysql_free_result(result);
        return (-2);
    }

    mysql_data_seek(result, 0);
    for (i = 0; i < num_rows; i++) {
        row = mysql_fetch_row(result);
        lengths = mysql_fetch_lengths(result);
        if (lengths == NULL) {
            LOG(LOG_ERR, "should never get here.  check mysql.mysql_fetch_lengths");
        }
        if (charp2uint32_t(&num, row[0], lengths[0])) {
            LOG(LOG_ERR, "could not convert field to number");
            mysql_free_result(result);
            return (-1);
        }
        if (num == sn)
            mysql_free_result(result);
            return (1);
    }

    mysql_free_result(result);
    return (0);
}


/*==============================================================================
 * @pre All rows in rtr_update are valid.
------------------------------------------------------------------------------*/
int startSerialQuery(void *connp, void **query_state, serial_number_t serial) {
    struct query_state *state;
    uint32_t next_ser_num = 0;

    if (serial != UINT32_MAX)  // TODO: change to use rtr_update.prev_serial_num
        next_ser_num = serial + 1;
    else
        next_ser_num = 0;

    state = calloc(1, sizeof(struct query_state));
    if (!state) {
        LOG(LOG_ERR, "could not alloc for query_state");
        return (-1);
    }
    state->ser_num = 0;
    state->first_row = 0;
    state->bad_ser_num = 0;
    state->data_sent = 0;
    state->no_new_data = 0;
    state->not_ready = 0;
    *query_state = (void*) state;

    // first check if next-ser-num is valid
    int ret = isValidSerNum(connp, next_ser_num);
    if (ret == -2) {
        state->not_ready = 1;
        return (0);
    }
    if (ret == 1) {
        state->ser_num = next_ser_num;
    } else if (ret == -1) {
        return (-1);
    } else {  // if not, then check if given-ser-num is valid
        ret = isValidSerNum(connp, serial);
        if (ret == 1) {
            state->no_new_data = 1;
        } else if (ret == -1) {
            return (-1);
        } else {
            state->bad_ser_num = 1;
        }
    }

    return (0);
}


/*==============================================================================
 * @param field_str has the format:  <address>/<length>(<max_length>)
 * It originates from a database field `ip_addr' and is null terminated
 *     before being passed to this function.
 * @return 0 on success or an error code on failure.
------------------------------------------------------------------------------*/
int parseIpaddr(uint *family, struct in_addr *addr4, struct in6_addr *addr6,
        uint *prefix_len, uint *max_len, const char field_str[]) {
    const size_t SZ = 40;  // max length of ipv6 string with \0
    char ip_txt[SZ];
    char prefix_len_txt[SZ];
    char max_len_txt[SZ];
    size_t ip_last;
    size_t prefix_first;
    size_t prefix_last;
    size_t max_first;
    size_t max_last;
    size_t i;

    // locate indices of the substrings
    ip_last = strcspn(field_str, "/") - 1;
    prefix_first = strcspn(field_str, "/") + 1;
    prefix_last = strcspn(field_str, "(") - 1;
    max_first = strcspn(field_str, "(") + 1;
    max_last = strcspn(field_str, ")") - 1;

    // check that all expected substring delimiters were found
    size_t in_len = strlen(field_str);
    if (in_len == ip_last ||
            in_len == prefix_first ||
            in_len == prefix_last ||
            in_len == max_first ||
            in_len == max_last) {
        LOG(LOG_ERR, "could not parse ip_addr:  %s", field_str);
        return (-1);
    }

    // retrieve the substrings
    for (i = 0; i <= ip_last && i < SZ - 1; i++) {
        ip_txt[i] = field_str[i];
    }
    ip_txt[i] = '\0';

    for (i = prefix_first; i <= prefix_last && i - prefix_first < SZ - 1; i++) {
        prefix_len_txt[i - prefix_first] = field_str[i];
    }
    prefix_len_txt[i - prefix_first] = '\0';

    for (i = max_first; i <= max_last && i - max_first < SZ - 1; i++) {
        max_len_txt[i - max_first] = field_str[i];
    }
    max_len_txt[i - max_first] = '\0';

    if (strcspn(ip_txt, ".") < strlen(ip_txt)) {
        *family = AF_INET;
        if (inet_pton(AF_INET, ip_txt, addr4) < 1) {
            LOG(LOG_ERR, "could not parse ip address text to in_addr");
            return (-1);
        }
    } else if (strcspn(ip_txt, ":") < strlen(ip_txt)) {
        *family = AF_INET6;
        if (inet_pton(AF_INET6, ip_txt, addr6) < 1) {
            LOG(LOG_ERR, "could not parse ip address text to in6_addr");
            return (-1);
        }
    } else {
        LOG(LOG_ERR, "could not parse ip_addr.family");
        return (-1);
    }

    if (sscanf(prefix_len_txt, "%u", prefix_len) < 1) {
        LOG(LOG_ERR, "could not parse ip_addr.prefix_length");
        return (-1);
    }

    if (sscanf(max_len_txt, "%u", max_len) < 1) {
        LOG(LOG_ERR, "could not parse ip_addr.max_prefix_length");
        return (-1);
    }

    return (0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
int fillPduFromDbResult(PDU **pdu, MYSQL_RES *result, cache_nonce_t nonce) {
    (void) pdu;  // to silence -Wunused-parameter

    // set protocolVersion
    (*pdu)->protocolVersion = RTR_PROTOCOL_VERSION;

    // set cacheNonce
    (*pdu)->cacheNonce = nonce;

    // collect info to set ipxPrefixData
    MYSQL_ROW row;

    row = mysql_fetch_row(result);

    // read is_announce from db
    char *is_announce_str;
    if (getStringByFieldname(&is_announce_str, result, row, "is_announce")) {
        LOG(LOG_ERR, "could not read is_announce");
        return (-1);
    }
    uint8_t is_announce;
    if (strcmp(is_announce_str, "0"))
        is_announce = 0;
    else if (strcmp(is_announce_str, "1"))
        is_announce = 1;
    else {
        LOG(LOG_ERR, "unexpected value for is_announce");
        return (-1);
    }
    if (is_announce_str) {
        free (is_announce_str);
        is_announce_str = NULL;
    }

    // read asn from db
    char *asn_str;
    if (getStringByFieldname(&asn_str, result, row, "asn")) {
        LOG(LOG_ERR, "could not read asn");
        return (-1);
    }
    uint32_t asn;
    if (sscanf(asn_str, "%" SCNu32, &asn) < 1) {
        LOG(LOG_ERR, "unexpected value for is_announce");
        return (-1);
    }
    if (asn_str) {
        free (asn_str);
        asn_str = NULL;
    }

    // read ip_addr from db
    char *ip_addr_str;
    if (getStringByFieldname(&ip_addr_str, result, row, "ip_addr")) {
        LOG(LOG_ERR, "could not read ip_addr");
        return (-1);
    }

    uint family = 0;
    struct in_addr addr4;
    struct in6_addr addr6;
    uint prefix_len = 0;
    uint max_prefix_len = 0;
    if (parseIpaddr(&family, &addr4, &addr6, &prefix_len, &max_prefix_len,
            ip_addr_str)) {
        LOG(LOG_ERR, "could not parse ip_addr");
        return (-1);
    }
    if (ip_addr_str) {
        free (ip_addr_str);
        ip_addr_str = NULL;
    }

    // check prefix lengths and max prefix lengths vs spec
    if ((family == AF_INET  &&  prefix_len > 32) ||
            (family == AF_INET6  &&  prefix_len > 128)) {
        LOG(LOG_ERR, "prefix length is out of spec");
        return (-1);
    }
    if ((family == AF_INET &&  max_prefix_len > 32) ||
            (family == AF_INET6 &&  max_prefix_len > 128)) {
        LOG(LOG_ERR, "max prefix length is out of spec");
        return (-1);
    }

    // set pduType {PDU_IPV4_PREFIX | PDU_IPV6_PREFIX}
    // set length
    // set IPxPrefixData
    if (family == AF_INET) {
        (*pdu)->pduType = PDU_IPV4_PREFIX;
        (*pdu)->length = htonl(20);
        (*pdu)->ip4PrefixData.flags = is_announce;
        (*pdu)->ip4PrefixData.prefixLength = prefix_len;
        (*pdu)->ip4PrefixData.maxLength = max_prefix_len;
        (*pdu)->ip4PrefixData.reserved = (uint8_t) 0;
        (*pdu)->ip4PrefixData.asNumber = htonl(asn);
        (*pdu)->ip4PrefixData.prefix4 = addr4;
    } else if (family == AF_INET6) {
        (*pdu)->pduType = PDU_IPV6_PREFIX;
        (*pdu)->length = htonl(32);
        (*pdu)->ip4PrefixData.flags = is_announce;
        (*pdu)->ip6PrefixData.prefixLength = prefix_len;
        (*pdu)->ip6PrefixData.maxLength = max_prefix_len;
        (*pdu)->ip6PrefixData.reserved = (uint8_t) 0;
        (*pdu)->ip6PrefixData.asNumber = htonl(asn);
        (*pdu)->ip6PrefixData.prefix6 = addr6;
    } else {
        LOG(LOG_ERR, "invalid ip family");
        return (-1);
    }

    return (0);
}


/*==============================================================================
 * If error, I call pdu_free_array(); else, caller does.
------------------------------------------------------------------------------*/
ssize_t serialQueryGetNext(void *connp, void *query_state, size_t max_rows,
        PDU **_pdus, bool *is_done) {
    size_t num_pdus = 0;
    PDU *pdus = NULL;
    struct query_state *state = (struct query_state*) query_state;
    cache_nonce_t nonce = 0;

    if (max_rows < 2) {
        LOG(LOG_ERR, "max_rows too small");
        *is_done = 1;
        return (-1);
    }

    pdus = calloc(max_rows, sizeof(PDU));
    if (!pdus) {
        LOG(LOG_ERR, "could not alloc for array of PDU");
        return (-1);
    }
    *_pdus = pdus;

    if (state->not_ready) {
        LOG(LOG_INFO, "no data is available to send to routers");
        // TODO: fill_pdu_error_report(&pdus[num_pdus++], NO_DATA_AVAILABLE);
        *is_done = 1;
        return (num_pdus);
    }

    if (state->bad_ser_num) {
        LOG(LOG_INFO, "can't update the router from the given serial number");
        fill_pdu_cache_reset(&pdus[num_pdus++]);
        *is_done = 1;
        return (num_pdus);
    }

    if (getCacheNonce(connp, &nonce)) {
        LOG(LOG_ERR, "couldn't get cache nonce");
        pdu_free_array(pdus, max_rows);
        return (-1);
    }

    if (state->no_new_data) {
        LOG(LOG_INFO, "no new data for the router from the given serial number");
        fill_pdu_cache_response(&pdus[num_pdus++], nonce);
        fill_pdu_end_of_data(&pdus[num_pdus++], nonce, state->ser_num);
        *is_done = 1;
        return (num_pdus);
    }

    if (!state->data_sent) {
        fill_pdu_cache_response(&pdus[num_pdus++], nonce);
        state->data_sent = 1;
    }

    MYSQL *mysqlp = (MYSQL*) connp;
    MYSQL_RES *result;
    my_ulonglong current_row = 0;
    my_ulonglong last_row = 0;
    int QRY_SZ = 256;
    char qry[QRY_SZ];
    uint32_t next_ser_num = 0;

    snprintf(qry, QRY_SZ, "select asn, ip_addr, is_announce from rtr_incremental "
            "where serial_num=%" PRIu32 " order by asn, ip_addr", state->ser_num);
    printf("query:  %s\n", qry);

    if (mysql_query(mysqlp, qry)) {
        LOG(LOG_ERR, "could not read rtr_incremental from db");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        pdu_free_array(pdus, max_rows);
        return (-1);
    }

    if ((result = mysql_store_result(mysqlp)) == NULL) {
        LOG(LOG_ERR, "could not read result set");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        pdu_free_array(pdus, max_rows);
        return (-1);
    }

    current_row = state->first_row;
    last_row = mysql_num_rows(result) - 1;

    if (current_row <= last_row)
        mysql_data_seek(result, current_row);

    while (current_row <= last_row  &&  num_pdus < max_rows) {
        if (fillPduFromDbResult(&(_pdus[num_pdus++]), result, nonce)) {
            LOG(LOG_ERR, "could not read result set");
            mysql_free_result(result);
            pdu_free_array(pdus, max_rows);
            return (-1);
        }
        current_row++;
    }

    if (num_pdus == max_rows) {
        state->first_row = current_row;
        mysql_free_result(result);
        return (num_pdus);
    } else {  // If we got here, then current_row > last_row.
        if (isValidSerNum(connp, state->ser_num)) {
            if (state->ser_num != UINT32_MAX)  // TODO: better way to find next-ser-num?
                next_ser_num = state->ser_num + 1;
            else
                next_ser_num = 0;

            if (isValidSerNum(connp, next_ser_num)) {
                state->ser_num = next_ser_num;
                state->first_row = 0;
                mysql_free_result(result);
                return (num_pdus);
            } else {
                fill_pdu_end_of_data(&pdus[num_pdus++], nonce, state->ser_num);
                *is_done = 1;
                mysql_free_result(result);
                return (num_pdus);
            }
        } else {
            LOG(LOG_INFO, "serial number became invalid after creating PDUs");
            num_pdus = 0;
            // TODO: fill_pdu_error_report(&pdus[num_pdus++], NO_DATA_AVAILABLE);
            *is_done = 1;
            return (num_pdus);
        }
    }
}


/*==============================================================================
------------------------------------------------------------------------------*/
void stopSerialQuery(void *connp, void * query_state) {
    (void) connp;  // to silence -Wunused-parameter
    free_query_state(query_state);

    return;
}


/*==============================================================================
------------------------------------------------------------------------------*/
int startResetQuery(void *connp, void ** query_state) {
    MYSQL *mysqlp = (MYSQL*) connp;

    (void) mysqlp;  // to silence -Wunused-parameter
    (void) query_state;  // to silence -Wunused-parameter

    return (0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
ssize_t resetQueryGetNext(void *connp, void * query_state, size_t max_rows,
        PDU ** pdus, bool * is_done) {
    MYSQL *mysqlp = (MYSQL*) connp;
    (void) mysqlp;  // to silence -Wunused-parameter
    (void) query_state;  // to silence -Wunused-parameter
    (void) max_rows;  // to silence -Wunused-parameter
    (void) pdus;  // to silence -Wunused-parameter
    (void) is_done;  // to silence -Wunused-parameter

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
 * @pre table rtr_nonce has exactly 0 or 1 rows.
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
