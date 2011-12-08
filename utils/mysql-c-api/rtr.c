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
 * @note Does not matter if serial_num is not null, or has_full.
 * @pre Each timestamp in rtr_update occurs in exactly 1 row.
 * @param[out] serial A return parameter for the serial number.
 * @return 0 if latest is found, a negative integer on error, a different
 *     negative integer if no rows found (but no error)
------------------------------------------------------------------------------*/
int getLatestSerialNumber(void *connp, serial_number_t *serial) {
    MYSQL *mysqlp = (MYSQL*) connp;
    MYSQL_RES *result;
    MYSQL_ROW row;
    char qry[] = "select serial_num from rtr_update "
            "order by create_time desc limit 1";

    if (serial == NULL) {
        LOG(LOG_ERR, "bad input");
        return (GET_SERNUM_ERR);
    }

    if (mysql_query(mysqlp, qry)) {
        LOG(LOG_ERR, "could not get latest serial number from db");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (GET_SERNUM_ERR);
    }

    if ((result = mysql_store_result(mysqlp)) == NULL) {
        LOG(LOG_ERR, "could not read result set");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (GET_SERNUM_ERR);
    }

    ulong *lengths;
    uint num_rows = mysql_num_rows(result);
    if (num_rows == 1) {
        row = mysql_fetch_row(result);
        lengths = mysql_fetch_lengths(result);  // mysql allocs the memory

        if (charp2uint32_t(serial, row[0], lengths[0])) {
            LOG(LOG_ERR, "error converting char[] to uint32_t for serial number");
            mysql_free_result(result);
            return (GET_SERNUM_ERR);
        }

        mysql_free_result(result);
        return (GET_SERNUM_SUCCESS);
    } else {  // num_rows == 0
        mysql_free_result(result);
        LOG(LOG_INFO, "returned 0 rows for query:  %s", qry);
        return (GET_SERNUM_NONE);
    }
}


/*==============================================================================
 * Probably obsolete.  If not used by Dec 19, 11, then delete
------------------------------------------------------------------------------
int isValidSerNumPrev(void *connp, uint32_t sn) {
    MYSQL *mysqlp = (MYSQL*) connp;
    MYSQL_RES *result;
    MYSQL_ROW row;

    return (VAL_SERNUM_IS_PREV);
}*/


/*==============================================================================
 * Probably obsolete.  If not used by Dec 19, 11, then delete
------------------------------------------------------------------------------
int isValidSerNumData(void *connp, uint32_t sn) {
    MYSQL *mysqlp = (MYSQL*) connp;
    MYSQL_RES *result;
    MYSQL_ROW row;
    int QRY_SZ = 256;
    char qry[QRY_SZ];

    snprintf(qry, QRY_SZ, "select serial_num, has_full from rtr_update "
            "where serial_num=%" PRIu32, sn);



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

    return (0);
}*/


/*==============================================================================
 * Probably obsolete.  If not used by Dec 19, 11, then delete
 * @pre serial_num is the first field in the rtr_update.
 * @ret 1 if serial number is found in rtr_update, -1 on error, 0 if serial
 *      number is not found, -2 if no rows are found.
------------------------------------------------------------------------------
int isValidSerNum(void *connp, uint32_t sn) {
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
}*/


/*==============================================================================
------------------------------------------------------------------------------*/
int getNumRowsInTable(void *connp, char *table_name) {
    MYSQL *mysqlp = (MYSQL*) connp;
    MYSQL_RES *result;
    int QRY_SZ = 256;
    char qry[QRY_SZ];

    snprintf(qry, QRY_SZ, "select count(*) from %s", table_name);

    if (mysql_query(mysqlp, qry)) {
        LOG(LOG_ERR, "could not read from db");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    if ((result = mysql_store_result(mysqlp)) == NULL) {
        LOG(LOG_ERR, "could not read result set");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    return ((int) mysql_num_rows(result));
}


/*==============================================================================
 * @param[in] ser_num_prev The serial_num to find in rtr_update.prev_serial_num.
 * @param[in] get_ser_num If non-zero, read serial_num.
 * @param[out] ser_num The value from the db.
 * @ret 0 if returning a value in ser_num, -1 for an unspecified error,
 *     1 if not returning a value in ser_num (but also no error)
------------------------------------------------------------------------------*/
int readSerNumAsPrev(void *connp, uint32_t ser_num_prev,
        int get_ser_num, uint32_t *ser_num){
    MYSQL *mysqlp = (MYSQL*) connp;
    MYSQL_RES *result;
    MYSQL_ROW row;
    int QRY_SZ = 256;
    char qry[QRY_SZ];
    int num_rows;
    char *ser_num_str = NULL;

    snprintf(qry, QRY_SZ, "select serial_num, prev_serial_num, has_full "
            "from rtr_update "
            "where prev_serial_num=%" PRIu32, ser_num_prev);

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
        mysql_free_result(result);
        return (1);
    } else if (num_rows > 1) {
        LOG(LOG_ERR, "unexpected result from rtr_update");
        mysql_free_result(result);
        return (-1);
    }

    if (!get_ser_num) {
        mysql_free_result(result);
        return (1);
    } else {
        row = mysql_fetch_row(result);
        if (getStringByFieldname(&ser_num_str, result, row, "serial_num")) {
            if (ser_num_str) {
                free (ser_num_str);
                ser_num_str = NULL;
            }
            mysql_free_result(result);
            return (-1);
        } else {
            if (sscanf(ser_num_str, "%" SCNu32, ser_num) < 1) {
                LOG(LOG_ERR, "unexpected value for serial number");
                return (-1);
            }
            if (ser_num_str) {
                free (ser_num_str);
                ser_num_str = NULL;
            }
            mysql_free_result(result);
            return (0);
        }
    }
}


/*==============================================================================
 * @param[in] serial The serial_num to find in rtr_update.serial_num.
 * @param[in] get_ser_num_prev If non-zero, read prev_serial_num.
 * @param[out] serial_prev The value from the db.
 * @param[out] prev_was_null self-explanatory.
 * @param[in] get_has_full If non-zero, read has_full.
 * @param[out] has_full The value from the db.
 * @ret 0 if ser num found and returning data, -1 if unspecified error,
 *     1 if ser num not found (but no error)
------------------------------------------------------------------------------*/
int readSerNumAsCurrent(void *connp, uint32_t serial,
        int get_ser_num_prev, uint32_t *serial_prev, int *prev_was_null,
        int get_has_full, int *has_full){
    MYSQL *mysqlp = (MYSQL*) connp;
    MYSQL_RES *result;
    MYSQL_ROW row;
    int QRY_SZ = 256;
    char qry[QRY_SZ];
    int num_rows;

    snprintf(qry, QRY_SZ, "select serial_num, prev_serial_num, has_full "
            "from rtr_update "
            "where serial_num=%" PRIu32, serial);

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
        mysql_free_result(result);
        return (1);
    } else if (num_rows > 1) {
        LOG(LOG_ERR, "unexpected result from rtr_update");
        mysql_free_result(result);
        return (-1);
    }

    row = mysql_fetch_row(result);

    char *sn_prev_str = NULL;
    if (get_ser_num_prev) {
        *prev_was_null = 0;
        if (getStringByFieldname(&sn_prev_str, result, row, "prev_serial_num")) {
            if (sn_prev_str) {
                free (sn_prev_str);
                sn_prev_str = NULL;
            }
            mysql_free_result(result);
            return (-1);
        } else {
            if (!strcmp(sn_prev_str, "NULL")) {
                *prev_was_null = 1;
                if (sn_prev_str) {
                    free (sn_prev_str);
                    sn_prev_str = NULL;
                }
                mysql_free_result(result);
                return (0);
            } else if (sscanf(sn_prev_str, "%" SCNu32, serial_prev) < 1) {
                LOG(LOG_ERR, "unexpected value for serial number");
                if (sn_prev_str) {
                    free (sn_prev_str);
                    sn_prev_str = NULL;
                }
                mysql_free_result(result);
                return (-1);
            }
        }
    }

    char *has_full_str = NULL;
    if (get_has_full) {
        if (getStringByFieldname(&has_full_str, result, row, "has_full")) {
            if (has_full_str) {
                free (has_full_str);
                has_full_str = NULL;
            }
            if (sn_prev_str) {
                free (sn_prev_str);
                sn_prev_str = NULL;
            }
            mysql_free_result(result);
            return (-1);
        } else {
            if (sscanf(has_full_str, "%d", has_full) < 1) {
                LOG(LOG_ERR, "unexpected value for has_full");
                if (has_full_str) {
                    free (has_full_str);
                    has_full_str = NULL;
                }
                if (sn_prev_str) {
                    free (sn_prev_str);
                    sn_prev_str = NULL;
                }
                mysql_free_result(result);
                return (-1);
            }
        }
    }

    if (sn_prev_str) {
        free (sn_prev_str);
        sn_prev_str = NULL;
    }
    if (has_full_str) {
        free (has_full_str);
        has_full_str = NULL;
    }
    mysql_free_result(result);
    return (0);
}


/*==============================================================================
 * @pre All rows in rtr_update are valid.
------------------------------------------------------------------------------*/
int startSerialQuery(void *connp, void **query_state, serial_number_t serial) {
    struct query_state *state = NULL;
    uint32_t serial_next = 0;
    int ret = 0;

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

    ret = readSerNumAsPrev(connp, serial, 1, &serial_next);
    if (ret == 0) {  // ser num found (as prev)
        state->ser_num = serial_next;
        return (0);
    } else if (ret == 1) {  // ser num not found (as prev)
        // continue after this if-block
    } else if (ret == -1) {  // some unspecified error
        return (-1);
    }

    ret = readSerNumAsCurrent(connp, serial, 0, NULL, NULL, 0, NULL);
    if (ret == 0) {  // ser num found (as current)
        state->no_new_data = 1;
        return (0);
    } else if (ret == 1) {  // ser num not found (as current)
        // continue after this if-block
    } else if (ret == -1) {  // some unspecified error
        return (-1);
    }

    ret = getNumRowsInTable(connp, "rtr_update");
    if (ret == -1) {
        LOG(LOG_ERR, "could not retrieve number of rows from rtr_update");
        return (-1);
    } else if (ret == 0) {  // rtr_update is empty
        state->not_ready = 1;
    } else if (ret > 0) {  // rtr_update is not empty,
        // but the given serial number is not recognized
        state->bad_ser_num = 1;
    }

    return (0);
}


/*==============================================================================
 * @param field_str has the format:  <address>/<length>[(<max_length>)]
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
    int max_found;

    // locate indices of the substrings' delimiters
    ip_last = strcspn(field_str, "/");
    prefix_first = strcspn(field_str, "/");
    prefix_last = strcspn(field_str, "(");
    max_first = strcspn(field_str, "(");
    max_last = strcspn(field_str, ")");

    // check that all expected substring delimiters were found
    // and check whether max_length was included
    size_t in_len = strlen(field_str);
    if (in_len != ip_last &&
            in_len != prefix_first &&
            in_len != prefix_last &&
            in_len != max_first &&
            in_len != max_last) {
        max_found = 1;
    } else if (in_len != ip_last &&
            in_len != prefix_first &&
            in_len == prefix_last) {
        max_found = 0;
    } else {
        LOG(LOG_ERR, "could not parse ip_addr:  %s", field_str);
        return (-1);
    }

    // adjust indices off of the delimiters and onto the substrings
    ip_last -= 1;
    prefix_first += 1;
    prefix_last -= 1;
    max_first += 1;
    max_last -= 1;

    // retrieve the substrings
    for (i = 0; i <= ip_last && i < SZ - 1; i++) {
        ip_txt[i] = field_str[i];
    }
    ip_txt[i] = '\0';

    for (i = prefix_first; i <= prefix_last && i - prefix_first < SZ - 1; i++) {
        prefix_len_txt[i - prefix_first] = field_str[i];
    }
    prefix_len_txt[i - prefix_first] = '\0';

    if (max_found) {
        for (i = max_first; i <= max_last && i - max_first < SZ - 1; i++) {
            max_len_txt[i - max_first] = field_str[i];
        }
        max_len_txt[i - max_first] = '\0';
    }

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

    if (max_found) {
        if (sscanf(max_len_txt, "%u", max_len) < 1) {
            LOG(LOG_ERR, "could not parse ip_addr.max_prefix_length");
            return (-1);
        }
    } else {
        if (*family == AF_INET)
            *max_len = *prefix_len;
        else
            *max_len = *prefix_len;
    }

    return (0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
int fillPduFromDbResult(PDU *pdu, MYSQL_RES *result, cache_nonce_t nonce,
        int check_is_announce) {
    pdu->protocolVersion = RTR_PROTOCOL_VERSION;
    pdu->cacheNonce = nonce;

    // collect info to set ipxPrefixData
    MYSQL_ROW row;
    row = mysql_fetch_row(result);

    // read is_announce from db
    uint8_t is_announce;
    char *is_announce_str;
    if (check_is_announce) {
        if (getStringByFieldname(&is_announce_str, result, row, "is_announce")) {
            LOG(LOG_ERR, "could not read is_announce");
            return (-1);
        }
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
    } else
        is_announce = 1;

    // read asn from db
    char *asn_str;
    if (getStringByFieldname(&asn_str, result, row, "asn")) {
        LOG(LOG_ERR, "could not read asn");
        return (-1);
    }
    uint32_t asn;
    if (sscanf(asn_str, "%" SCNu32, &asn) < 1) {
        LOG(LOG_ERR, "unexpected value for asn");
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
        pdu->pduType = PDU_IPV4_PREFIX;
        pdu->length = 20;
        pdu->ip4PrefixData.flags = is_announce;
        pdu->ip4PrefixData.prefixLength = prefix_len;
        pdu->ip4PrefixData.maxLength = max_prefix_len;
        pdu->ip4PrefixData.reserved = (uint8_t) 0;
        pdu->ip4PrefixData.asNumber = asn;
        pdu->ip4PrefixData.prefix4 = addr4;
    } else if (family == AF_INET6) {
        pdu->pduType = PDU_IPV6_PREFIX;
        pdu->length = 32;
        pdu->ip4PrefixData.flags = is_announce;
        pdu->ip6PrefixData.prefixLength = prefix_len;
        pdu->ip6PrefixData.maxLength = max_prefix_len;
        pdu->ip6PrefixData.reserved = (uint8_t) 0;
        pdu->ip6PrefixData.asNumber = asn;
        pdu->ip6PrefixData.prefix6 = addr6;
    } else {
        LOG(LOG_ERR, "invalid ip family");
        return (-1);
    }

    return (0);
}


/*==============================================================================
 * @note see rtr.h about when to set is_done to 0 or 1.
 * @note If error, I call pdu_free_array(); else, caller does.
------------------------------------------------------------------------------*/
ssize_t serialQueryGetNext(void *connp, void *query_state, size_t max_rows,
        PDU **_pdus, bool *is_done) {
    size_t num_pdus = 0;
    PDU *pdus = NULL;
    struct query_state *state = (struct query_state*) query_state;
    cache_nonce_t nonce = 0;
    int ret = 0;

    *is_done = 1;

    if (max_rows < 2) {
        LOG(LOG_ERR, "max_rows too small");
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
        fill_pdu_error_report(&((*_pdus)[num_pdus++]), ERR_NO_DATA, 0, NULL, 0, NULL);
        LOG(LOG_INFO, "returning %u PDUs", num_pdus);
        return (num_pdus);
    }

    if (state->bad_ser_num) {
        LOG(LOG_INFO, "can't update the router from the given serial number");
        fill_pdu_cache_reset(&((*_pdus)[num_pdus++]));
        LOG(LOG_INFO, "returning %u PDUs", num_pdus);
        return (num_pdus);
    }

    if (getCacheNonce(connp, &nonce)) {
        LOG(LOG_ERR, "couldn't get cache nonce");
        pdu_free_array(pdus, max_rows);
        return (-1);
    }

    if (state->no_new_data) {
        LOG(LOG_INFO, "no new data for the router from the given serial number");
        fill_pdu_cache_response(&((*_pdus)[num_pdus++]), nonce);
        LOG(LOG_INFO, "calling fill_pdu_end_of_data()");
        fill_pdu_end_of_data(&((*_pdus)[num_pdus++]), nonce, state->ser_num);
        LOG(LOG_INFO, "returning %u PDUs", num_pdus);
        return (num_pdus);
    }

    if (!state->data_sent) {
        fill_pdu_cache_response(&((*_pdus)[num_pdus++]), nonce);
        state->data_sent = 1;
    }

    MYSQL *mysqlp = (MYSQL*) connp;
    MYSQL_RES *result;
    my_ulonglong current_row = 0;
    my_ulonglong last_row = 0;
    int QRY_SZ = 256;
    char qry[QRY_SZ];
    uint32_t next_ser_num;
    uint32_t prev_ser_num;
    int prev_was_null;

    snprintf(qry, QRY_SZ, "select asn, ip_addr, is_announce from rtr_incremental "
            "where serial_num=%" PRIu32 " order by asn, ip_addr", state->ser_num);

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
        if (fillPduFromDbResult(&((*_pdus)[num_pdus++]), result, nonce, 1)) {
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
        *is_done = 0;
        LOG(LOG_INFO, "returning %u PDUs", num_pdus);
        return (num_pdus);
    } else {  // If we're here, current_row > last_row, num_pdus < max_rows
        ret = readSerNumAsCurrent(connp, state->ser_num,
                1, &prev_ser_num, &prev_was_null,
                0, NULL);
        if (ret == -1) {
            LOG(LOG_ERR, "error while checking validity of serial number");
            pdu_free_array(pdus, max_rows);
            mysql_free_result(result);
            return (-1);
        } else if (prev_was_null) {
            LOG(LOG_INFO, "serial number became invalid after creating PDUs");
            fill_pdu_error_report(&((*_pdus)[num_pdus++]), ERR_NO_DATA, 0, NULL, 0, NULL);
            mysql_free_result(result);
            LOG(LOG_INFO, "returning %u PDUs", num_pdus);
            return (num_pdus);
        } else {
            // check whether to End or continue with next ser num
            ret = readSerNumAsPrev(connp, state->ser_num, 1, &next_ser_num);
            if (ret == 0) {  // db has sn_next for this sn
                *is_done = 0;
                state->ser_num = next_ser_num;
                state->first_row = 0;
                mysql_free_result(result);
                LOG(LOG_INFO, "returning %u PDUs", num_pdus);
                return (num_pdus);
            } else if (ret == 1) {  // db has no sn_next for this sn
                LOG(LOG_INFO, "calling fill_pdu_end_of_data()");
                fill_pdu_end_of_data(&((*_pdus)[num_pdus++]), nonce, state->ser_num);
                mysql_free_result(result);
                LOG(LOG_INFO, "returning %u PDUs", num_pdus);
                return (num_pdus);
            } else {
                // NOTE:  even though error, still feeding previous results,
                //     which should be unaffected by this error.
                LOG(LOG_ERR, "error while looking for next serial number");
                LOG(LOG_INFO, "calling fill_pdu_end_of_data()");
                fill_pdu_end_of_data(&((*_pdus)[num_pdus++]), nonce, state->ser_num);
                mysql_free_result(result);
                LOG(LOG_INFO, "returning %u PDUs", num_pdus);
                return (num_pdus);
            }
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
    struct query_state *state = NULL;
    int ret = 0;

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

    ret = getLatestSerialNumber(connp, &state->ser_num);
    if (ret) {
        LOG(LOG_ERR, "error getting latest serial number");
        if (state) free(state);
        return (-1);
    }

//    uint32_t ser_num_prev;  // I don't use the value, but the called fcn wants a place to put it.
//    int prev_was_null = 0;
    int has_full;
    ret = readSerNumAsCurrent(connp, state->ser_num, 0, NULL, NULL,
            1, &has_full);
//    ret = readSerNumAsCurrent(connp, ser_num, 0, &ser_num_prev, &prev_was_null,
//            0, &has_full);
    if (ret) {
        LOG(LOG_ERR, "error reading data about latest serial number");
        if (state) free(state);
        return (-1);
    }
    if (!has_full) {
        LOG(LOG_INFO, "data not yet available");
        state->not_ready = 1;
        return (0);
    }

    // data ready to send
    return (0);
}


/*==============================================================================
 * If error, I call pdu_free_array(); else, caller does.
------------------------------------------------------------------------------*/
ssize_t resetQueryGetNext(void *connp, void * query_state, size_t max_rows,
        PDU ** _pdus, bool * is_done) {
    size_t num_pdus = 0;
    PDU *pdus = NULL;
    struct query_state *state = (struct query_state*) query_state;
    cache_nonce_t nonce = 0;
    int ret = 0;

    *is_done = 1;

    if (max_rows < 2) {
        LOG(LOG_ERR, "max_rows too small");
        return (-1);
    }

    pdus = calloc(max_rows, sizeof(PDU));
    if (!pdus) {
        LOG(LOG_ERR, "could not alloc for array of PDU");
        return (-1);
    }
    *_pdus = pdus;

    if (getCacheNonce(connp, &nonce)) {
        LOG(LOG_ERR, "couldn't get cache nonce");
        pdu_free_array(pdus, max_rows);
        return (-1);
    }

    if (state->not_ready) {
        LOG(LOG_INFO, "no data is available to send to routers");
        fill_pdu_error_report(&((*_pdus)[num_pdus++]), ERR_NO_DATA, 0, NULL, 0, NULL);
        LOG(LOG_INFO, "returning %u PDUs", num_pdus);
        return (num_pdus);
    }

    if (!state->data_sent) {
        fill_pdu_cache_response(&((*_pdus)[num_pdus++]), nonce);
        state->data_sent = 1;
    }

    MYSQL *mysqlp = (MYSQL*) connp;
    MYSQL_RES *result;
    my_ulonglong current_row = 0;
    my_ulonglong last_row = 0;
    int QRY_SZ = 256;
    char qry[QRY_SZ];

    snprintf(qry, QRY_SZ, "select asn, ip_addr from rtr_full "
            "where serial_num=%" PRIu32 " order by asn, ip_addr", state->ser_num);

    if (mysql_query(mysqlp, qry)) {
        LOG(LOG_ERR, "could not read rtr_full from db");
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
        if (fillPduFromDbResult(&((*_pdus)[num_pdus++]), result, nonce, 0)) {
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
        *is_done = 0;
        LOG(LOG_INFO, "returning %u PDUs", num_pdus);
        return (num_pdus);
    } else {  // If we're here, current_row > last_row, num_pdus < max_rows
        ret = readSerNumAsCurrent(connp, state->ser_num,
                0, NULL, NULL,
                0, NULL);
        if (ret == -1) {
            LOG(LOG_ERR, "error while checking validity of serial number");
            mysql_free_result(result);
            pdu_free_array(pdus, max_rows);
            return (-1);
        } else {
            LOG(LOG_INFO, "calling fill_pdu_end_of_data()");
            fill_pdu_end_of_data(&((*_pdus)[num_pdus++]), nonce, state->ser_num);
            mysql_free_result(result);
            LOG(LOG_INFO, "returning %u PDUs", num_pdus);
            return (num_pdus);
        }
    }

    return (0);
}


/*==============================================================================
------------------------------------------------------------------------------*/
void stopResetQuery(void *connp, void * query_state) {
    (void) connp;  // to silence -Wunused-parameter
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
