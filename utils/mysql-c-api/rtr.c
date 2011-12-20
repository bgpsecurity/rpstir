/**
	Functions used for accessing the RTR database.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include <my_global.h>
#include <mysql.h>

#include "connect.h"
#include "db-internal.h"
#include "logging.h"
#include "prep-stmt.h"
#include "rtr.h"
#include "util.h"


struct query_state {
    uint32_t ser_num;  // ser_num to search for first row to send
    uint first_row;    // first row to send.  zero-based
    int bad_ser_num;   // neither the given ser_num, nor its successor, exist
    int data_sent;     // true if a pdu has been created for this serial/reset query
    int no_new_data;   // the given ser_num exists, but its successor does not
    int not_ready;     // no valid ser_nums exist, yet
    uint16_t session;
};


/**=============================================================================
------------------------------------------------------------------------------*/
void free_query_state(void *qs) {
    if (qs)
        free (qs);
    qs = NULL;
}


/**=============================================================================
------------------------------------------------------------------------------*/
/*
int db_rtr_get_session_id_old(conn *conn, session_id_t *session) {
    MYSQL *mysql = conn->mysql;
    MYSQL_RES *result;
    MYSQL_ROW row;
    const char qry[] = "select session_id from rtr_session";

    if (wrap_mysql_query(conn, qry, "could not get session_id from db")) {
        return -1;
    }

    if ((result = mysql_store_result(mysql)) == NULL) {
        LOG(LOG_ERR, "could not read result set");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
        return -1;
    }

    uint num_rows = mysql_num_rows(result);
    char *session_id_str = NULL;
    if (num_rows == 1) {
        row = mysql_fetch_row(result);
        if (getStringByFieldname(&session_id_str, result, row, "session_id")) {
            if (session_id_str) {
                free (session_id_str);
                session_id_str = NULL;
            }
            mysql_free_result(result);
            return -1;
        } else {
            if (sscanf(session_id_str, "%" SCNu16, session) < 1) {
                LOG(LOG_ERR, "unexpected value for session_id");
                return -1;
            }
            if (session_id_str) {
                free (session_id_str);
                session_id_str = NULL;
            }
            mysql_free_result(result);
            return 0;
        }
    } else {
        mysql_free_result(result);
        LOG(LOG_ERR, "returned %u rows for query:  %s", num_rows, qry);
        return -1;
    }
}
 */


/**=============================================================================
------------------------------------------------------------------------------*/
int db_rtr_get_session_id(dbconn *conn, session_id_t *session) {
    MYSQL_STMT *stmt = conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_GET_SESSION];
    int ret;
    ulong length[1];
    uint16_t data;
    my_bool is_null[1];
    my_bool error[1];

    if (wrap_mysql_stmt_execute(conn, stmt, "mysql_stmt_execute() failed")) {
        return -1;
    }

    MYSQL_BIND bind[1];
    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type= MYSQL_TYPE_SHORT;
    bind[0].buffer= &data;
    bind[0].is_null= &is_null[0];
    bind[0].length= &length[0];
    bind[0].error= &error[0];

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

    ret = mysql_stmt_fetch(stmt);
    if (ret == 1  ||  ret == MYSQL_DATA_TRUNCATED) {
        LOG(LOG_ERR, "mysql_stmt_fetch() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    //    if (is_null[0])
    //        fprintf(stdout, "NULL\n");
    //    else
    //        fprintf(stdout,"%" PRIu16 "(%ld)\n", data, length[0]);

    *session = data;
    mysql_stmt_free_result(stmt);

    return 0;
}


/**=============================================================================
 * @note Does not matter if serial_num is not null, or has_full.
 * @pre Each timestamp in rtr_update occurs in exactly 1 row.
 * @param[out] serial A return parameter for the serial number.
 * @return 0 if latest is found, a negative integer on error, a different
 *     negative integer if no rows found (but no error)
------------------------------------------------------------------------------*/
int db_rtr_get_latest_sernum(dbconn *conn, serial_number_t *serial) {
    MYSQL *mysql = conn->mysql;
    MYSQL_RES *result;
    MYSQL_ROW row;
    char qry[] = "select serial_num from rtr_update "
            "order by create_time desc limit 1";

    if (serial == NULL) {
        LOG(LOG_ERR, "bad input");
        return GET_SERNUM_ERR;
    }

    //    if (wrap_mysql_query(conn, qry)) {
    if (wrap_mysql_query(conn, qry, "could not get latest serial number from db")) {
        return GET_SERNUM_ERR;
    }

    if ((result = mysql_store_result(mysql)) == NULL) {
        LOG(LOG_ERR, "could not read result set");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
        return GET_SERNUM_ERR;
    }

    uint num_rows = mysql_num_rows(result);
    char *sn_str = NULL;
    if (num_rows == 1) {
        row = mysql_fetch_row(result);
        if (getStringByFieldname(&sn_str, result, row, "serial_num")) {
            if (sn_str) {
                free (sn_str);
                sn_str = NULL;
            }
            mysql_free_result(result);
            return GET_SERNUM_ERR;
        } else {
            if (sscanf(sn_str, "%" SCNu32, serial) < 1) {
                LOG(LOG_ERR, "unexpected value for serial_num");
                return GET_SERNUM_ERR;
            }
            if (sn_str) {
                free (sn_str);
                sn_str = NULL;
            }
            mysql_free_result(result);
            return GET_SERNUM_SUCCESS;
        }
    } else {  // num_rows == 0
        mysql_free_result(result);
        LOG(LOG_DEBUG, "returned 0 rows for query:  %s", qry);
        return GET_SERNUM_NONE;
    }
}


/**=============================================================================
------------------------------------------------------------------------------*/
int getNumRowsInTable(dbconn *conn, char *table_name) {
    MYSQL *mysql = conn->mysql;
    MYSQL_RES *result;
    int QRY_SZ = 256;
    char qry[QRY_SZ];

    snprintf(qry, QRY_SZ, "select count(*) from %s", table_name);

    if (wrap_mysql_query(conn, qry, "could not read from db")) {
        return -1;
    }

    if ((result = mysql_store_result(mysql)) == NULL) {
        LOG(LOG_ERR, "could not read result set");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
        return -1;
    }

    return ((int) mysql_num_rows(result));
}


/**=============================================================================
 * @brief Get info from db row where ser_num_prev = rtr_update.prev_serial_num.
 * @param[in] ser_num_prev The serial_num to find in rtr_update.prev_serial_num.
 * @param[in] get_ser_num If non-zero, read serial_num.
 * @param[out] ser_num The value from the db.
 * @ret 0 if returning a value in ser_num, -1 for an unspecified error,
 *     1 if not returning a value in ser_num (but also no error)
------------------------------------------------------------------------------*/
int readSerNumAsPrev(dbconn *conn, uint32_t ser_num_prev,
        int get_ser_num, uint32_t *ser_num){
    MYSQL *mysql = conn->mysql;
    MYSQL_RES *result;
    MYSQL_ROW row;
    int QRY_SZ = 256;
    char qry[QRY_SZ];
    int num_rows;
    char *ser_num_str = NULL;

    snprintf(qry, QRY_SZ, "select serial_num, prev_serial_num, has_full "
            "from rtr_update "
            "where prev_serial_num=%" PRIu32, ser_num_prev);

    if (wrap_mysql_query(conn, qry, "could not read rtr_update from db")) {
        return -1;
    }

    if ((result = mysql_store_result(mysql)) == NULL) {
        LOG(LOG_ERR, "could not read result set");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
        return -1;
    }

    num_rows = mysql_num_rows(result);
    if (num_rows == 0) {
        mysql_free_result(result);
        return 1;
    } else if (num_rows > 1) {
        LOG(LOG_ERR, "unexpected result from rtr_update");
        mysql_free_result(result);
        return -1;
    }

    if (!get_ser_num) {
        mysql_free_result(result);
        return 1;
    } else {
        row = mysql_fetch_row(result);
        if (getStringByFieldname(&ser_num_str, result, row, "serial_num")) {
            if (ser_num_str) {
                free (ser_num_str);
                ser_num_str = NULL;
            }
            mysql_free_result(result);
            return -1;
        } else {
            if (sscanf(ser_num_str, "%" SCNu32, ser_num) < 1) {
                LOG(LOG_ERR, "unexpected value for serial number");
                return -1;
            }
            if (ser_num_str) {
                free (ser_num_str);
                ser_num_str = NULL;
            }
            mysql_free_result(result);
            return 0;
        }
    }
}


/**=============================================================================
 * @brief Get info from db row where serial = rtr_update.serial_num.
 * @param[in] serial The serial_num to find in rtr_update.serial_num.
 * @param[in] get_ser_num_prev If non-zero, read prev_serial_num.
 * @param[out] serial_prev The value from the db.
 * @param[out] prev_was_null self-explanatory.
 * @param[in] get_has_full If non-zero, read has_full.
 * @param[out] has_full The value from the db.
 * @ret 0 if ser num found and returning data, -1 if unspecified error,
 *     1 if ser num not found (but no error)
------------------------------------------------------------------------------*/
int readSerNumAsCurrent(dbconn *conn, uint32_t serial,
        int get_ser_num_prev, uint32_t *serial_prev, int *prev_was_null,
        int get_has_full, int *has_full){
    MYSQL *mysql = conn->mysql;
    MYSQL_RES *result;
    MYSQL_ROW row;
    int QRY_SZ = 256;
    char qry[QRY_SZ];
    int num_rows;

    snprintf(qry, QRY_SZ, "select serial_num, prev_serial_num, has_full "
            "from rtr_update "
            "where serial_num=%" PRIu32, serial);

    if (wrap_mysql_query(conn, qry, "could not read rtr_update from db")) {
        return -1;
    }

    if ((result = mysql_store_result(mysql)) == NULL) {
        LOG(LOG_ERR, "could not read result set");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
        return -1;
    }

    num_rows = mysql_num_rows(result);
    if (num_rows == 0) {
        mysql_free_result(result);
        return 1;
    } else if (num_rows > 1) {
        LOG(LOG_ERR, "unexpected result from rtr_update");
        mysql_free_result(result);
        return -1;
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
            return -1;
        } else {
            if (!strcmp(sn_prev_str, "NULL")) {
                *prev_was_null = 1;
                if (sn_prev_str) {
                    free (sn_prev_str);
                    sn_prev_str = NULL;
                }
                mysql_free_result(result);
                return 0;
            } else if (sscanf(sn_prev_str, "%" SCNu32, serial_prev) < 1) {
                LOG(LOG_ERR, "unexpected value for serial number");
                if (sn_prev_str) {
                    free (sn_prev_str);
                    sn_prev_str = NULL;
                }
                mysql_free_result(result);
                return -1;
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
            return -1;
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
                return -1;
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
    return 0;
}


/**=============================================================================
 * @param field_str has the format:  <address>/<length>[(<max_length>)]
 * It originates from a database field `ip_addr' and gets null terminated
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
        return -1;
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
            return -1;
        }
    } else if (strcspn(ip_txt, ":") < strlen(ip_txt)) {
        *family = AF_INET6;
        if (inet_pton(AF_INET6, ip_txt, addr6) < 1) {
            LOG(LOG_ERR, "could not parse ip address text to in6_addr");
            return -1;
        }
    } else {
        LOG(LOG_ERR, "could not parse ip_addr.family");
        return -1;
    }

    if (sscanf(prefix_len_txt, "%u", prefix_len) < 1) {
        LOG(LOG_ERR, "could not parse ip_addr.prefix_length");
        return -1;
    }

    if (max_found) {
        if (sscanf(max_len_txt, "%u", max_len) < 1) {
            LOG(LOG_ERR, "could not parse ip_addr.max_prefix_length");
            return -1;
        }
    } else {
        if (*family == AF_INET)
            *max_len = *prefix_len;
        else
            *max_len = *prefix_len;
    }

    return 0;
}


/**=============================================================================
------------------------------------------------------------------------------*/
int fillPduIpPrefix(PDU *pdu, uint32_t asn, char *ip_addr, int is_announce,
        session_id_t session) {
    pdu->protocolVersion = RTR_PROTOCOL_VERSION;
    pdu->sessionId = session;

    uint family = 0;
    struct in_addr addr4;
    struct in6_addr addr6;
    uint prefix_len = 0;
    uint max_prefix_len = 0;
    if (parseIpaddr(&family, &addr4, &addr6, &prefix_len, &max_prefix_len,
            ip_addr)) {
        LOG(LOG_ERR, "could not parse ip_addr");
        return -1;
    }

    // check prefix lengths and max prefix lengths vs spec
    if ((family == AF_INET  &&  prefix_len > 32) ||
            (family == AF_INET6  &&  prefix_len > 128)) {
        LOG(LOG_ERR, "prefix length is out of spec");
        return -1;
    }
    if ((family == AF_INET &&  max_prefix_len > 32) ||
            (family == AF_INET6 &&  max_prefix_len > 128)) {
        LOG(LOG_ERR, "max prefix length is out of spec");
        return -1;
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
        pdu->ip6PrefixData.flags = is_announce;
        pdu->ip6PrefixData.prefixLength = prefix_len;
        pdu->ip6PrefixData.maxLength = max_prefix_len;
        pdu->ip6PrefixData.reserved = (uint8_t) 0;
        pdu->ip6PrefixData.asNumber = asn;
        pdu->ip6PrefixData.prefix6 = addr6;
    } else {
        LOG(LOG_ERR, "invalid ip family");
        return -1;
    }

    return 0;
}


/**=============================================================================
------------------------------------------------------------------------------*/
int fillPduFromDbResult(PDU *pdu, MYSQL_RES *result, session_id_t session,
        int check_is_announce) {
    pdu->protocolVersion = RTR_PROTOCOL_VERSION;
    pdu->sessionId = session;

    // collect info to set ipxPrefixData
    MYSQL_ROW row;
    row = mysql_fetch_row(result);

    // read is_announce from db
    uint8_t is_announce;
    char *is_announce_str;
    if (check_is_announce) {
        if (getStringByFieldname(&is_announce_str, result, row, "is_announce")) {
            LOG(LOG_ERR, "could not read is_announce");
            return -1;
        }
        if (!strncmp(is_announce_str, "0", 1))
            is_announce = 0;
        else if (!strncmp(is_announce_str, "1", 1))
            is_announce = 1;
        else {
            LOG(LOG_ERR, "unexpected value for is_announce");
            return -1;
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
        return -1;
    }
    uint32_t asn;
    if (sscanf(asn_str, "%" SCNu32, &asn) < 1) {
        LOG(LOG_ERR, "unexpected value for asn");
        return -1;
    }
    if (asn_str) {
        free (asn_str);
        asn_str = NULL;
    }

    // read ip_addr from db
    char *ip_addr_str;
    if (getStringByFieldname(&ip_addr_str, result, row, "ip_addr")) {
        LOG(LOG_ERR, "could not read ip_addr");
        return -1;
    }

    uint family = 0;
    struct in_addr addr4;
    struct in6_addr addr6;
    uint prefix_len = 0;
    uint max_prefix_len = 0;
    if (parseIpaddr(&family, &addr4, &addr6, &prefix_len, &max_prefix_len,
            ip_addr_str)) {
        LOG(LOG_ERR, "could not parse ip_addr");
        return -1;
    }
    if (ip_addr_str) {
        free (ip_addr_str);
        ip_addr_str = NULL;
    }

    // check prefix lengths and max prefix lengths vs spec
    if ((family == AF_INET  &&  prefix_len > 32) ||
            (family == AF_INET6  &&  prefix_len > 128)) {
        LOG(LOG_ERR, "prefix length is out of spec");
        return -1;
    }
    if ((family == AF_INET &&  max_prefix_len > 32) ||
            (family == AF_INET6 &&  max_prefix_len > 128)) {
        LOG(LOG_ERR, "max prefix length is out of spec");
        return -1;
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
        pdu->ip6PrefixData.flags = is_announce;
        pdu->ip6PrefixData.prefixLength = prefix_len;
        pdu->ip6PrefixData.maxLength = max_prefix_len;
        pdu->ip6PrefixData.reserved = (uint8_t) 0;
        pdu->ip6PrefixData.asNumber = asn;
        pdu->ip6PrefixData.prefix6 = addr6;
    } else {
        LOG(LOG_ERR, "invalid ip family");
        return -1;
    }

    return 0;
}


/**=============================================================================
 * @pre All rows in rtr_update are valid.
------------------------------------------------------------------------------*/
int db_rtr_serial_query_init(dbconn *conn, void **query_state, serial_number_t serial) {
    struct query_state *state = NULL;
    uint32_t serial_next = 0;
    int ret = 0;

    state = calloc(1, sizeof(struct query_state));
    if (!state) {
        LOG(LOG_ERR, "could not alloc for query_state");
        return -1;
    }
    state->ser_num = 0;
    state->first_row = 0;
    state->bad_ser_num = 0;
    state->data_sent = 0;
    state->no_new_data = 0;
    state->not_ready = 0;
    *query_state = (void*) state;

    ret = readSerNumAsPrev(conn, serial, 1, &serial_next);
    if (ret == 0) {  // ser num found (as prev)
        state->ser_num = serial_next;
        return 0;
    } else if (ret == 1) {  // ser num not found (as prev)
        // continue after this if-block
    } else if (ret == -1) {  // some unspecified error
        return -1;
    }

    ret = readSerNumAsCurrent(conn, serial, 0, NULL, NULL, 0, NULL);
    if (ret == 0) {  // ser num found (as current)
        state->ser_num = serial;
        state->no_new_data = 1;
        return 0;
    } else if (ret == 1) {  // ser num not found (as current)
        // continue after this if-block
    } else if (ret == -1) {  // some unspecified error
        return -1;
    }

    ret = getNumRowsInTable(conn, "rtr_update");
    if (ret == -1) {
        LOG(LOG_ERR, "could not retrieve number of rows from rtr_update");
        return -1;
    } else if (ret == 0) {  // rtr_update is empty
        state->not_ready = 1;
    } else if (ret > 0) {  // rtr_update is not empty,
        // but the given serial number is not recognized
        state->bad_ser_num = 1;
    }

    return 0;
}


/**=============================================================================
------------------------------------------------------------------------------*/
int serial_query_pre_query(dbconn *conn, void *query_state,
        size_t max_rows, PDU **_pdus, size_t *num_pdus) {
    PDU *pdus = *_pdus;
    struct query_state *state = (struct query_state*) query_state;

    if (max_rows < 2) {
        LOG(LOG_ERR, "max_rows too small");
        return -1;
    }

    if (state->not_ready) {
        LOG(LOG_INFO, "no data is available to send to routers");
        fill_pdu_error_report(&((*_pdus)[(*num_pdus)++]), ERR_NO_DATA, 0, NULL, 0, NULL);
        LOG(LOG_INFO, "returning %zu PDUs", *num_pdus);
        return *num_pdus;
    }

    if (state->bad_ser_num) {
        LOG(LOG_INFO, "can't update the router from the given serial number");
        fill_pdu_cache_reset(&((*_pdus)[(*num_pdus)++]));
        LOG(LOG_INFO, "returning %zu PDUs", *num_pdus);
        return *num_pdus;
    }

    if (db_rtr_get_session_id(conn, &(state->session))) {
        LOG(LOG_ERR, "couldn't get session id");
        pdu_free_array(pdus, max_rows);
        return -1;
    }

    if (state->no_new_data) {
        LOG(LOG_INFO, "no new data for the router from the given serial number");
        fill_pdu_cache_response(&((*_pdus)[(*num_pdus)++]), state->session);
        LOG(LOG_INFO, "calling fill_pdu_end_of_data()");
        fill_pdu_end_of_data(&((*_pdus)[(*num_pdus)++]), state->session, state->ser_num);
        LOG(LOG_INFO, "returning %zu PDUs", *num_pdus);
        return *num_pdus;
    }

    if (!state->data_sent) {
        fill_pdu_cache_response(&((*_pdus)[(*num_pdus)++]), state->session);
        state->data_sent = 1;
    }

    return *num_pdus;
}


/**=============================================================================
------------------------------------------------------------------------------*/
ssize_t serial_query_do_query(dbconn *conn, void *query_state,
        size_t max_rows, PDU **_pdus, size_t *num_pdus) {
    struct query_state *state = (struct query_state*) query_state;
    int ret;

    MYSQL_STMT *stmt = conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_SERIAL_QRY_GET_NEXT];
    MYSQL_BIND bind_in[3];

    MYSQL_BIND bind_out[3];
    uint32_t asn;
    const size_t IPADDR_STR_LEN = 50;
    char ip_addr[IPADDR_STR_LEN + 1];
    unsigned char is_announce;

    memset(bind_in, 0, sizeof(bind_in));
    // serial_num parameter
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].is_unsigned = 1;
    bind_in[0].buffer = &(state->ser_num);
    // offset parameter
    bind_in[1].buffer_type = MYSQL_TYPE_LONG;
    bind_in[1].is_unsigned = 1;
    bind_in[1].buffer = &(state->first_row);
    // limit parameter
    bind_in[2].buffer_type = MYSQL_TYPE_LONG;
    bind_in[2].is_unsigned = 1;
    size_t limit = max_rows - *num_pdus;
    bind_in[2].buffer = &limit;

    if (mysql_stmt_bind_param(stmt, bind_in)) {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        return -1;
    }

    if (wrap_mysql_stmt_execute(conn, stmt, "could not retrieve data from rtr_incremental")) {
        return -1;
    }

    memset(bind_out, 0, sizeof(bind_out));
    // asn output
    bind_out[0].buffer_type = MYSQL_TYPE_LONG;
    bind_out[0].is_unsigned = 1;
    bind_out[0].buffer = (char*)&asn;
    // ip_addr output
    bind_out[1].buffer_type = MYSQL_TYPE_STRING;
    bind_out[1].buffer_length = IPADDR_STR_LEN;
    bind_out[1].buffer = (char*)&ip_addr;
    // is_announce output
    bind_out[2].buffer_type = MYSQL_TYPE_TINY;
    bind_out[2].is_unsigned = 1;
    bind_out[2].buffer = (char*)&is_announce;

    if (mysql_stmt_bind_result(stmt, bind_out)) {
        LOG(LOG_ERR, "mysql_stmt_bind_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    // mysql_stmt_store_result is optional.  mysql_stmt_fetch will produce the
    //   same data whether or not it is called.  But calling it brings the
    //   whole result from the db at one time.
    if (mysql_stmt_store_result(stmt)) {
        LOG(LOG_ERR, "mysql_stmt_store_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    while ((ret = mysql_stmt_fetch(stmt)) == 0) {
        if (fillPduIpPrefix(&((*_pdus)[(*num_pdus)++]), asn, ip_addr,
                is_announce, state->session)) {
            LOG(LOG_ERR, "could not create PDU_IPVx_PREFIX");
            mysql_stmt_free_result(stmt);
            return -1;
        }
        ++state->first_row;
    }
    if (ret == 1  ||  ret == MYSQL_DATA_TRUNCATED) {
        LOG(LOG_ERR, "error during mysql_stmt_fetch()");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }
    mysql_stmt_free_result(stmt);

    return 0;
}


/**=============================================================================
------------------------------------------------------------------------------*/
ssize_t serial_query_post_query(dbconn *conn, void *query_state,
        size_t max_rows, PDU **_pdus, size_t *num_pdus, bool *is_done) {
    struct query_state *state = (struct query_state*) query_state;
    int ret;

    uint32_t next_ser_num;
    uint32_t prev_ser_num;
    int prev_was_null;

    // check whether sn is still valid
    ret = readSerNumAsCurrent(conn, state->ser_num,
            1, &prev_ser_num, &prev_was_null,
            0, NULL);
    if (prev_was_null) {
        LOG(LOG_INFO, "serial number became invalid after creating PDUs");
        fill_pdu_error_report(&((*_pdus)[(*num_pdus)++]), ERR_NO_DATA, 0, NULL, 0, NULL);
        LOG(LOG_INFO, "returning %zu PDUs", *num_pdus);
        return *num_pdus;
    } else if (ret == -1) {
        LOG(LOG_ERR, "error while checking validity of serial number");
        pdu_free_array(*_pdus, max_rows);
        return -1;
    }

    // check whether to End or continue with next ser num
    ret = readSerNumAsPrev(conn, state->ser_num, 1, &next_ser_num);
    if (ret == 0) {  // db has sn_next for this sn
        *is_done = 0;
        state->ser_num = next_ser_num;
        state->first_row = 0;
        LOG(LOG_INFO, "returning %zu PDUs", *num_pdus);
        return *num_pdus;
    } else if (ret == 1) {  // db has no sn_next for this sn
        LOG(LOG_INFO, "calling fill_pdu_end_of_data()");
        fill_pdu_end_of_data(&((*_pdus)[(*num_pdus)++]), state->session, state->ser_num);
        LOG(LOG_INFO, "returning %zu PDUs", *num_pdus);
        return *num_pdus;
    }

    // NOTE:  even though error, still feeding previous results,
    //     which should be unaffected by this error.
    LOG(LOG_ERR, "error while looking for next serial number");
    LOG(LOG_INFO, "calling fill_pdu_end_of_data()");
    fill_pdu_end_of_data(&((*_pdus)[(*num_pdus)++]), state->session, state->ser_num);
    LOG(LOG_INFO, "returning %zu PDUs", *num_pdus);
    return *num_pdus;
}


/**=============================================================================
 * @note see rtr.h about when to set is_done to 0 or 1.
 * @note If error, I call pdu_free_array(); else, caller does.
------------------------------------------------------------------------------*/
ssize_t db_rtr_serial_query_get_next(dbconn *conn, void *query_state,
        size_t max_rows, PDU **_pdus, bool *is_done) {
    PDU *pdus = NULL;
    struct query_state *state = (struct query_state*) query_state;
    size_t num_pdus = 0;
    int ret;

    *is_done = 1;

    pdus = calloc(max_rows, sizeof(PDU));
    if (!pdus) {
        LOG(LOG_ERR, "could not alloc for array of PDU");
        return -1;
    }
    *_pdus = pdus;

    if (!state->data_sent) {
        ret = serial_query_pre_query(conn, state, max_rows, _pdus, &num_pdus);
        if (ret == -1) {
            return -1;
        } else if (state->not_ready || state->bad_ser_num || state->no_new_data) {
            return num_pdus;
        }
    }

    ret = serial_query_do_query(conn, state, max_rows, _pdus, &num_pdus);
    if (ret == -1) {
        pdu_free_array(*_pdus, max_rows);
        return -1;
    }
    if (num_pdus == max_rows) {
        *is_done = 0;
        LOG(LOG_INFO, "returning %zu PDUs", num_pdus);
        return num_pdus;
    }

    ret = serial_query_post_query(conn, state, max_rows, _pdus, &num_pdus, is_done);

    return num_pdus;
}


/**=============================================================================
------------------------------------------------------------------------------*/
void db_rtr_serial_query_close(dbconn *conn, void * query_state) {
    (void) conn;  // to silence -Wunused-parameter
    free_query_state(query_state);
}


/**=============================================================================
------------------------------------------------------------------------------*/
int db_rtr_reset_query_init(dbconn *conn, void ** query_state) {
    struct query_state *state = NULL;
    int ret = 0;

    state = calloc(1, sizeof(struct query_state));
    if (!state) {
        LOG(LOG_ERR, "could not alloc for query_state");
        return -1;
    }
    state->ser_num = 0;
    state->first_row = 0;
    state->bad_ser_num = 0;
    state->data_sent = 0;
    state->no_new_data = 0;
    state->not_ready = 0;
    *query_state = (void*) state;

    ret = db_rtr_get_latest_sernum(conn, &state->ser_num);
    if (ret) {
        LOG(LOG_ERR, "error getting latest serial number");
        if (state) free(state);
        return -1;
    }

    int has_full;
    ret = readSerNumAsCurrent(conn, state->ser_num, 0, NULL, NULL,
            1, &has_full);
    if (ret) {
        LOG(LOG_ERR, "error reading data about latest serial number");
        if (state) free(state);
        return -1;
    }
    if (!has_full) {
        LOG(LOG_INFO, "data not yet available");
        state->not_ready = 1;
        return 0;
    }

    // data ready to send
    return 0;
}


/**=============================================================================
 * @note If error, I call pdu_free_array(); else, caller does.
------------------------------------------------------------------------------*/
ssize_t db_rtr_reset_query_get_next(dbconn *conn, void * query_state, size_t max_rows,
        PDU ** _pdus, bool * is_done) {
    size_t num_pdus = 0;
    PDU *pdus = NULL;
    struct query_state *state = (struct query_state*) query_state;
    session_id_t session = 0;

    *is_done = 1;

    if (max_rows < 2) {
        LOG(LOG_ERR, "max_rows too small");
        return -1;
    }

    // alloc enough for max_rows + header & footer PDUs
    pdus = calloc(max_rows + 2, sizeof(PDU));
    if (!pdus) {
        LOG(LOG_ERR, "could not alloc for array of PDU");
        return -1;
    }
    *_pdus = pdus;

    if (state->not_ready) {
        LOG(LOG_INFO, "no data is available to send to routers");
        fill_pdu_error_report(&((*_pdus)[num_pdus++]), ERR_NO_DATA, 0, NULL, 0, NULL);
        LOG(LOG_INFO, "returning %zu PDUs", num_pdus);
        return num_pdus;
    }

    if (db_rtr_get_session_id(conn, &session)) {
        LOG(LOG_ERR, "couldn't get session id");
        pdu_free_array(pdus, max_rows);
        return -1;
    }

    if (!state->data_sent) {
        fill_pdu_cache_response(&((*_pdus)[num_pdus++]), session);
        state->data_sent = 1;
    }

    MYSQL *mysql = conn->mysql;
    MYSQL_RES *result;
    my_ulonglong num_rows = 0;
    int QRY_SZ = 256;
    char qry[QRY_SZ];

    snprintf(qry, QRY_SZ, "select asn, ip_addr "
            " from rtr_full "
            " where serial_num=%" PRIu32
            " order by asn, ip_addr"
            " limit %u, %zu",
            state->ser_num, state->first_row, max_rows - num_pdus);

    if (wrap_mysql_query(conn, qry, "could not read rtr_full from db")) {
        pdu_free_array(pdus, max_rows);
        return -1;
    }

    if ((result = mysql_store_result(mysql)) == NULL) {
        LOG(LOG_ERR, "could not read result set");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
        pdu_free_array(pdus, max_rows);
        return -1;
    }

    num_rows = mysql_num_rows(result);

    while (num_rows > 0) {
        if (fillPduFromDbResult(&((*_pdus)[num_pdus++]), result, session, 0)) {
            LOG(LOG_ERR, "could not read result set");
            mysql_free_result(result);
            pdu_free_array(pdus, max_rows);
            return -1;
        }
        --num_rows;
        ++state->first_row;
    }

    if (num_pdus == max_rows) {
        mysql_free_result(result);
        *is_done = 0;
        LOG(LOG_INFO, "returning %zu PDUs", num_pdus);
        return num_pdus;
    }

    // See draft-ietf-sidr-rpki-rtr-19, section 5.4 Cache Response
    // Even if there is a newer sn, don't feed it.  rtr_incremental may contain
    //     a withdrawal, which must not be sent during a Cache Response.

    LOG(LOG_INFO, "calling fill_pdu_end_of_data()");
    fill_pdu_end_of_data(&((*_pdus)[num_pdus++]), session, state->ser_num);
    mysql_free_result(result);
    LOG(LOG_INFO, "returning %zu PDUs", num_pdus);
    return num_pdus;
}


/**=============================================================================
------------------------------------------------------------------------------*/
void db_rtr_reset_query_close(dbconn *conn, void * query_state) {
    (void) conn;  // to silence -Wunused-parameter
    free_query_state(query_state);
}


/**=============================================================================
 * not currently an API function.  currently for testing
 * @pre table rtr_session has exactly 0 or 1 rows.
 * NOTE: If this becomes used beyond testing, check that old_session != new_session.
------------------------------------------------------------------------------*/
int setSessionId(dbconn *conn, uint16_t session) {
    MYSQL *mysql = conn->mysql;
    const char qry_delete[] = "delete from rtr_session";
    const int QRY_SZ = 256;
    char qry_insert[QRY_SZ];

    if (wrap_mysql_query(conn, qry_delete, "could not delete from rtr_session")) {
        return -1;
    }

    snprintf(qry_insert, QRY_SZ, "insert into rtr_session (session_id) "
            "value (%u)", session);

    if (wrap_mysql_query(conn, qry_insert, "could not insert into rtr_session")) {
        return -1;
    }

    int rows;
    if ((rows = mysql_affected_rows(mysql)) != 1) {
        LOG(LOG_ERR, "failed to insert db.rtr_session.session_id=%u", session);
        LOG(LOG_ERR, "affected rows = %d", rows);
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
        return -1;
    }

    return 0;
}


/**=============================================================================
 * This function is only for testing.  Someone else is responsible for inserting
 *   records into rtr_update.
------------------------------------------------------------------------------*/
int addNewSerNum(dbconn *conn, const uint32_t *in) {
    MYSQL *mysql = conn->mysql;
    uint32_t latest_ser_num = 0;
    uint32_t new_ser_num = 0;
    const int QRY_SZ = 1024;
    char qry[QRY_SZ];

    if (in) {
        new_ser_num = *in;
    } else if (db_rtr_get_latest_sernum(conn, &latest_ser_num) == 0) {
        if (latest_ser_num != 0xffffffff)
            new_ser_num = latest_ser_num + 1;
        else
            new_ser_num = 0;
    } else {
        LOG(LOG_ERR, "error reading latest serial number");
        return -1;
    }

    // Note:  Silently deleting the serial_num I am about to insert.
    // Assumption:  it is no longer needed.
    snprintf(qry, QRY_SZ, "delete from rtr_update where serial_num=%u",
            new_ser_num);

    if (wrap_mysql_query(conn, qry, "could not delete serial number from db")) {
        return -1;
    }

    if (mysql_affected_rows(mysql))
        LOG(LOG_INFO, "serial_num %u had to be deleted from db before inserting it", new_ser_num);

    snprintf(qry, QRY_SZ, "insert into rtr_update values (%u, now())",
            new_ser_num);

    if (wrap_mysql_query(conn, qry, "could not add new serial number to db")) {
        return -1;
    }

    return 0;
}


/**=============================================================================
 * This function is only for testing.  Someone else is responsible for deleting
 *   records from rtr_update.
------------------------------------------------------------------------------*/
int deleteSerNum(dbconn *conn, uint32_t ser_num) {
    MYSQL *mysql = conn->mysql;
    const int QRY_SZ = 1024;
    char qry[QRY_SZ];

    snprintf(qry, QRY_SZ, "delete from rtr_update where serial_num=%u",
            ser_num);

    if (wrap_mysql_query(conn, qry, "could not delete serial number from db")) {
        return -1;
    }

    LOG(LOG_DEBUG, "%llu rows affected for '%s'", mysql_affected_rows(mysql), qry);

    return 0;
}


/**=============================================================================
 * This function is only for testing.  Someone else is responsible for deleting
 *   records from rtr_update.
------------------------------------------------------------------------------*/
int deleteAllSerNums(dbconn *conn) {
    const char qry[] = "delete from rtr_update";

    LOG(LOG_ERR, "x");
    if (wrap_mysql_query(conn, qry, "could not delete all serial numbers from db")) {
        return -1;
    }

    return 0;
}
