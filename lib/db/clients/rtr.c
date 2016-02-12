/**
   Functions used for accessing the RTR database.
 */

#include "rtr.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include <mysql.h>

#include "config/config.h"
#include "db/connect.h"
#include "db/db-internal.h"
#include "util/logging.h"
#include "util/macros.h"
#include "db/prep-stmt.h"
#include "db/util.h"


struct query_state {
    /**
        @brief Serial number to search for first row to send.
    */
    uint32_t ser_num;

    /**
        @brief The last row that we sent.
    */
    struct last_row {
        /**
            @brief False if there was a previous row, true if this is
                the first time.

            If this is true, the values in the remaining fields are
            unspecified.
        */
        unsigned char first_time;

        unsigned asn;

        /**
            @brief Length of #prefix, either 4 for IPv4 or 16 for IPv6.
        */
        uint8_t prefix_family_length;

        unsigned char prefix[16];

        unsigned char prefix_length;

        unsigned char prefix_max_length;
    } first_row;

    /**
        @brief Neither the given ser_num, nor its successor, exist.
    */
    int bad_ser_num;

    /**
        @brief True if a pdu has been created for this serial/reset query.
    */
    int data_sent;

    /**
        @brief The given ser_num exists, but its successor does not.
    */
    int no_new_data;

    /**
        @brief No valid ser_nums exist, yet.
    */
    int not_ready;

    /**
        @brief The session_id number.
    */
    uint16_t session;
};


/**=============================================================================
------------------------------------------------------------------------------*/
int db_rtr_get_session_id(
    dbconn * conn,
    session_id_t * session)
{
    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_GET_SESSION];
    int ret;

    MYSQL_BIND bind_in[1];
    uint32_t limit = 2;         // 2 keeps the fetch small while letting
                                // num_rows() ensure there's only one row in
                                // the table
    memset(bind_in, 0, sizeof(bind_in));
    // limit number of rows to return
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].buffer = &limit;
    bind_in[0].is_unsigned = (my_bool) 1;
    bind_in[0].is_null = (my_bool *) 0;
    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        return -1;
    }

    if (wrap_mysql_stmt_execute(
        conn, stmt,
        "mysql_stmt_execute(DB_PSTMT_RTR_GET_SESSION) failed"))
    {
        return -1;
    }

    MYSQL_BIND bind_out[1];
    memset(bind_out, 0, sizeof(bind_out));
    uint16_t db_session;
    // session_id parameter
    bind_out[0].buffer_type = MYSQL_TYPE_SHORT;
    bind_out[0].is_unsigned = 1;
    bind_out[0].buffer = &db_session;

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
        LOG(LOG_ERR, "more or less than one session id exists");
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

    *session = db_session;
    mysql_stmt_free_result(stmt);

    return 0;
}


/**=============================================================================
 * @note Does not matter if serial_num is not null, or has_full.
 * @pre Each timestamp in rtr_update occurs in exactly 1 row.
 * @param[out] serial A return parameter for the serial number.
 * @ret GET_SERNUM_SUCCESS if given sn found as a previous-sn.,
 *      GET_SERNUM_ERR for an unspecified error,
 *      GET_SERNUM_NONE if given sn not found as a previous-sn. (but no error)
------------------------------------------------------------------------------*/
int db_rtr_get_latest_sernum(
    dbconn * conn,
    serial_number_t * serial)
{
    // "select serial_num from rtr_update order by create_time desc limit 1"
    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_GET_LATEST_SERNUM];
    int ret;

    if (wrap_mysql_stmt_execute(
        conn, stmt,
        "mysql_stmt_execute(DB_PSTMT_RTR_GET_LATEST_SERNUM) failed"))
    {
        return GET_SERNUM_ERR;
    }

    MYSQL_BIND bind_out[1];
    memset(bind_out, 0, sizeof(bind_out));
    uint32_t db_sn;
    // serial_num
    bind_out[0].buffer_type = MYSQL_TYPE_LONG;
    bind_out[0].is_unsigned = (my_bool) 1;
    bind_out[0].buffer = &db_sn;

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

    ret = mysql_stmt_fetch(stmt);
    if (ret == 0)
    {
        *serial = db_sn;
        mysql_stmt_free_result(stmt);
        return GET_SERNUM_SUCCESS;
    }
    else if (ret == MYSQL_NO_DATA)
    {
        mysql_stmt_free_result(stmt);
        return GET_SERNUM_NONE;
    }
    else
    {
        LOG(LOG_ERR, "mysql_stmt_fetch() failed");
        if (ret == 1)
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
                mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return GET_SERNUM_ERR;
    }
}


/**=============================================================================
 * @ret 0 if no rows, 1 if rows, -1 on error.
------------------------------------------------------------------------------*/
static int hasRowsRtrUpdate(
    dbconn * conn)
{
    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_HAS_ROWS_RTR_UPDATE];
    int ret;

    if (wrap_mysql_stmt_execute(
        conn, stmt,
        "mysql_stmt_execute(DB_PSTMT_RTR_HAS_ROWS_RTR_UPDATE) failed"))
    {
        return -1;
    }

    MYSQL_BIND bind_out[1];
    memset(bind_out, 0, sizeof(bind_out));
    uint32_t db_has_rows = 0;
    bind_out[0].buffer_type = MYSQL_TYPE_LONG;
    bind_out[0].is_unsigned = (my_bool) 1;
    bind_out[0].buffer = &db_has_rows;

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

    mysql_stmt_free_result(stmt);

    if (db_has_rows)
        return 1;
    else
        return 0;
}


/**=============================================================================
 * @brief Get info from db row where ser_num_prev = rtr_update.prev_serial_num.
 * @param[in] ser_num_prev The serial_num to find in rtr_update.prev_serial_num.
 * @param[in] get_ser_num If non-zero, read serial_num.
 * @param[out] ser_num The value from the db.
 * @ret GET_SERNUM_SUCCESS if given sn found as a previous-sn.,
 *      GET_SERNUM_ERR for an unspecified error,
 *      GET_SERNUM_NONE if given sn not found as a previous-sn. (but no error)
------------------------------------------------------------------------------*/
static int readSerNumAsPrev(
    dbconn * conn,
    uint32_t ser_num_prev,
    int get_ser_num,
    uint32_t * ser_num)
{
    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_READ_SER_NUM_AS_PREV];
    int ret;

    MYSQL_BIND bind_in[1];
    memset(bind_in, 0, sizeof(bind_in));
    // prev_serial_num parameter
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].buffer = &ser_num_prev;
    bind_in[0].is_unsigned = (my_bool) 1;
    bind_in[0].is_null = (my_bool *) 0;
    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        return GET_SERNUM_ERR;
    }

    if (wrap_mysql_stmt_execute(
        conn, stmt,
        "mysql_stmt_execute(DB_PSTMT_RTR_READ_SER_NUM_AS_PREV) failed"))
    {
        return GET_SERNUM_ERR;
    }

    uint32_t db_sn;
    MYSQL_BIND bind_out[1];
    memset(bind_out, 0, sizeof(bind_out));
    // serial_num
    bind_out[0].buffer_type = MYSQL_TYPE_LONG;
    bind_out[0].buffer = &db_sn;
    bind_out[0].is_unsigned = (my_bool) 1;

    if (mysql_stmt_bind_result(stmt, bind_out))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return GET_SERNUM_ERR;
    }

    if (mysql_stmt_store_result(stmt))
    {
        LOG(LOG_ERR, "mysql_stmt_store_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return GET_SERNUM_ERR;
    }

    ret = mysql_stmt_fetch(stmt);
    if (ret == 0)
    {
        if (get_ser_num)
        {
            *ser_num = db_sn;
        }

        mysql_stmt_free_result(stmt);
        return GET_SERNUM_SUCCESS;
    }
    else if (ret == MYSQL_NO_DATA)
    {
        mysql_stmt_free_result(stmt);
        return GET_SERNUM_NONE;
    }
    else
    {
        LOG(LOG_ERR, "mysql_stmt_fetch() failed");
        if (ret == 1)
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
                mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return GET_SERNUM_ERR;
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
 * @ret GET_SERNUM_SUCCESS if given sn found as a current-sn.,
 *      GET_SERNUM_ERR for an unspecified error,
 *      GET_SERNUM_NONE if given sn not found as a current-sn. (but no error)
------------------------------------------------------------------------------*/
static int readSerNumAsCurrent(
    dbconn * conn,
    uint32_t serial,
    int get_ser_num_prev,
    uint32_t * serial_prev,
    int *prev_was_null,
    int get_has_full,
    int *has_full)
{
    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_READ_SER_NUM_AS_CURRENT];
    int ret;

    MYSQL_BIND bind_in[1];
    memset(bind_in, 0, sizeof(bind_in));
    // serial_num parameter
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].buffer = &serial;
    bind_in[0].is_unsigned = (my_bool) 1;
    bind_in[0].is_null = (my_bool *) 0;
    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        return GET_SERNUM_ERR;
    }

    if (wrap_mysql_stmt_execute(
        conn, stmt,
        "mysql_stmt_execute(DB_PSTMT_RTR_READ_SER_NUM_AS_CURRENT) failed"))
    {
        return GET_SERNUM_ERR;
    }

    my_bool db_is_null_prev_sn;
    int8_t db_has_full;
    uint32_t db_prev_sn;
    MYSQL_BIND bind_out[2];
    memset(bind_out, 0, sizeof(bind_out));
    // prev_serial_num
    bind_out[0].buffer_type = MYSQL_TYPE_LONG;
    bind_out[0].buffer = &db_prev_sn;
    bind_out[0].is_unsigned = (my_bool) 1;
    bind_out[0].is_null = &db_is_null_prev_sn;
    // has_full
    bind_out[1].buffer_type = MYSQL_TYPE_TINY;
    bind_out[1].buffer = &db_has_full;
    bind_out[1].is_unsigned = (my_bool) 0;

    if (mysql_stmt_bind_result(stmt, bind_out))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return GET_SERNUM_ERR;
    }

    if (mysql_stmt_store_result(stmt))
    {
        LOG(LOG_ERR, "mysql_stmt_store_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return GET_SERNUM_ERR;
    }

    ret = mysql_stmt_fetch(stmt);
    if (ret == 1 || ret == MYSQL_DATA_TRUNCATED)
    {
        LOG(LOG_ERR, "mysql_stmt_fetch() failed");
        if (ret == 1)
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
                mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return GET_SERNUM_ERR;
    }
    else if (ret == MYSQL_NO_DATA)
    {
        mysql_stmt_free_result(stmt);
        return GET_SERNUM_NONE;
    }

    if (get_ser_num_prev)
    {
        if (prev_was_null == NULL || serial_prev == NULL)
        {
            LOG(LOG_ERR, "got NULL parameter");
            mysql_stmt_free_result(stmt);
            return GET_SERNUM_ERR;
        }

        *serial_prev = db_prev_sn;

        if (db_is_null_prev_sn)
        {
            *prev_was_null = 1;
        }
        else
        {
            *prev_was_null = 0;
        }
    }

    if (get_has_full && has_full != NULL)
        *has_full = (int)db_has_full;

    mysql_stmt_free_result(stmt);
    return GET_SERNUM_SUCCESS;
}


/**=============================================================================
 * @param[out] pdu PDU to fill in.
 * @param[in] asn AS number.
 * @param[in] prefix_data Raw prefix.
 * @param[in] prefix_data_length Length of @p prefix_data. This must be either
 *    4 (IPv4) or 16 (IPv6).
 * @param[in] prefix_length Length in bits of the prefix. This must be >= 0, and
 *    <= 32 for IPv4 or <= 128 for IPv6.
 * @param[in] prefix_max_length Maximum prefix length, as from a ROA.
 * @param[in] is_announce True for announcement, false for withdrawal.
------------------------------------------------------------------------------*/
static int fillPduIpPrefix(
    PDU * pdu,
    uint32_t asn,
    uint8_t const * prefix_data,
    size_t prefix_data_length,
    uint8_t prefix_length,
    uint8_t prefix_max_length,
    bool is_announce)
{
    struct in_addr in_addr;
    struct in6_addr in6_addr;
    uint8_t flags = is_announce ? FLAG_WITHDRAW_ANNOUNCE : 0;

    switch (prefix_data_length)
    {
        case 4:
            memcpy(&in_addr.s_addr, prefix_data, prefix_data_length);
            fill_pdu_ipv4_prefix(pdu, flags, prefix_length,
                prefix_max_length, &in_addr, asn);
            break;

        case 16:
            memcpy(&in6_addr.s6_addr, prefix_data, prefix_data_length);
            fill_pdu_ipv6_prefix(pdu, flags, prefix_length,
                prefix_max_length, &in6_addr, asn);
            break;

        default:
            return -1;
    }

    return 0;
}


/**=============================================================================
 * @pre All rows in rtr_update are valid.
------------------------------------------------------------------------------*/
int db_rtr_serial_query_init(
    dbconn * conn,
    void **query_state,
    serial_number_t serial)
{
    struct query_state *state = NULL;
    uint32_t serial_next = 0;
    int64_t ret = 0;

    state = calloc(1, sizeof(struct query_state));
    if (!state)
    {
        LOG(LOG_ERR, "could not alloc for query_state");
        return -1;
    }
    state->ser_num = 0;
    state->first_row.first_time = 1;
    state->bad_ser_num = 0;
    state->data_sent = 0;
    state->no_new_data = 0;
    state->not_ready = 0;
    *query_state = (void *)state;


    // If sn is in prev_serial_num, then send data.
    ret = readSerNumAsPrev(conn, serial, 1, &serial_next);
    if (ret == GET_SERNUM_SUCCESS)
    {                           // ser num found (as prev)
        state->ser_num = serial_next;
        return 0;
    }
    else if (ret == GET_SERNUM_NONE)
    {                           // ser num not found (as prev)
        // continue after this if-block
    }
    else if (ret == GET_SERNUM_ERR)
    {                           // some unspecified error
        free(state);
        *query_state = NULL;
        return -1;
    }

    // If sn is in serial_num, then send no-new-data.
    ret = readSerNumAsCurrent(conn, serial, 0, NULL, NULL, 0, NULL);
    if (ret == GET_SERNUM_SUCCESS)
    {                           // ser num found (as current)
        state->ser_num = serial;
        state->no_new_data = 1;
        return 0;
    }
    else if (ret == GET_SERNUM_NONE)
    {                           // ser num not found (as current)
        // continue after this if-block
    }
    else if (ret == GET_SERNUM_ERR)
    {                           // some unspecified error
        free(state);
        *query_state = NULL;
        return -1;
    }

    // If rtr_update is not empty, then send cache reset.
    // If rtr_update is empty, then send no-data-available.
    // The session_id and serial_num will never become valid in the
    // second case, but RFC6810 section 6.4 says to send
    // no-data-available.
    ret = hasRowsRtrUpdate(conn);
    if (ret == -1)
    {
        LOG(LOG_ERR, "could not retrieve number of rows from rtr_update");
        free(state);
        *query_state = NULL;
        return -1;
    }
    else if (ret == 0)
    {                           // rtr_update is empty
        state->not_ready = 1;
    }
    else if (ret > 0)
    {                           // rtr_update is not empty,
        // but the given serial number is not recognized
        state->bad_ser_num = 1;
    }

    return 0;
}


/**=============================================================================
@return -1 on error, 1 if the query is done, 0 otherwise
------------------------------------------------------------------------------*/
static int serial_query_pre_query(
    dbconn * conn,
    void *query_state,
    size_t max_rows,
    PDU ** _pdus,
    size_t * num_pdus)
{
    struct query_state *state = (struct query_state *)query_state;

    if (max_rows < 2)
    {
        LOG(LOG_ERR, "max_rows too small");
        return -1;
    }

    if (state->not_ready)
    {
        LOG(LOG_DEBUG, "no data is available to send to routers");
        fill_pdu_error_report(&((*_pdus)[(*num_pdus)++]), ERR_NO_DATA, 0, NULL,
                              0, NULL);
        LOG(LOG_DEBUG, "returning %zu PDUs", *num_pdus);
        return 1;
    }

    if (state->bad_ser_num)
    {
        LOG(LOG_DEBUG, "can't update the router from the given serial number");
        fill_pdu_cache_reset(&((*_pdus)[(*num_pdus)++]));
        LOG(LOG_DEBUG, "returning %zu PDUs", *num_pdus);
        return 1;
    }

    if (db_rtr_get_session_id(conn, &(state->session)))
    {
        LOG(LOG_ERR, "couldn't get session id");
        return -1;
    }

    if (state->no_new_data)
    {
        LOG(LOG_DEBUG,
            "no new data for the router from the given serial number");
        fill_pdu_cache_response(&((*_pdus)[(*num_pdus)++]), state->session);
        LOG(LOG_DEBUG, "calling fill_pdu_end_of_data()");
        fill_pdu_end_of_data(&((*_pdus)[(*num_pdus)++]), state->session,
                             state->ser_num);
        LOG(LOG_DEBUG, "returning %zu PDUs", *num_pdus);
        return 1;
    }

    if (!state->data_sent)
    {
        fill_pdu_cache_response(&((*_pdus)[(*num_pdus)++]), state->session);
        state->data_sent = 1;
    }

    return 0;
}


/**=============================================================================
------------------------------------------------------------------------------*/
static int serial_query_do_query(
    dbconn * conn,
    void *query_state,
    size_t max_rows,
    PDU ** _pdus,
    size_t * num_pdus)
{
    struct query_state *state = (struct query_state *)query_state;
    int ret;
    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_SERIAL_QRY_GET_NEXT];

    MYSQL_BIND bind_in[7];
    memset(bind_in, 0, sizeof(bind_in));
    // serial_num parameter
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].buffer = &(state->ser_num);
    bind_in[0].is_unsigned = (my_bool) 1;
    bind_in[0].is_null = (my_bool *) 0;
    // start-at-beginning parameter
    bind_in[1].buffer_type = MYSQL_TYPE_TINY;
    bind_in[1].buffer = &state->first_row.first_time;
    bind_in[1].is_unsigned = (my_bool)1;
    bind_in[1].is_null = (my_bool *)0;
    // asn parameter
    bind_in[2].buffer_type = MYSQL_TYPE_LONG;
    bind_in[2].buffer = &state->first_row.asn;
    bind_in[2].is_unsigned = (my_bool)1;
    bind_in[2].is_null = (my_bool *)0;
    // prefix parameter
    bind_in[3].buffer_type = MYSQL_TYPE_BLOB;
    bind_in[3].buffer = &state->first_row.prefix;
    bind_in[3].buffer_length = sizeof(state->first_row.prefix);
    unsigned long prefix_family_length;
    if (state->first_row.first_time)
    {
        prefix_family_length = 0;
    }
    else
    {
        prefix_family_length = state->first_row.prefix_family_length;
    }
    bind_in[3].length = &prefix_family_length;
    bind_in[3].is_null = (my_bool *)0;
    // prefix_length parameter
    bind_in[4].buffer_type = MYSQL_TYPE_TINY;
    bind_in[4].buffer = &state->first_row.prefix_length;
    bind_in[4].is_unsigned = (my_bool)1;
    bind_in[4].is_null = (my_bool *)0;
    // prefix_max_length parameter
    bind_in[5].buffer_type = MYSQL_TYPE_TINY;
    bind_in[5].buffer = &state->first_row.prefix_max_length;
    bind_in[5].is_unsigned = (my_bool)1;
    bind_in[5].is_null = (my_bool *)0;
    // limit parameter
    bind_in[6].buffer_type = MYSQL_TYPE_LONGLONG;
    unsigned long long limit = max_rows - *num_pdus;
    bind_in[6].buffer = &limit;
    bind_in[6].is_unsigned = (my_bool) 1;
    bind_in[6].is_null = (my_bool *) 0;


    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        return -1;
    }

    if (wrap_mysql_stmt_execute
        (conn, stmt, "could not retrieve data from rtr_incremental"))
    {
        return -1;
    }

    MYSQL_BIND bind_out[5];
    unsigned db_asn;
    unsigned long db_prefix_family_length;
    unsigned char db_prefix[16];
    unsigned char db_prefix_length;
    unsigned char db_prefix_max_length;
    signed char db_is_announce;
    memset(bind_out, 0, sizeof(bind_out));
    // asn output
    bind_out[0].buffer_type = MYSQL_TYPE_LONG;
    bind_out[0].is_unsigned = (my_bool) 1;
    bind_out[0].buffer = &db_asn;
    // prefix output
    bind_out[1].buffer_type = MYSQL_TYPE_BLOB;
    bind_out[1].buffer_length = sizeof(db_prefix);
    bind_out[1].length = &db_prefix_family_length;
    bind_out[1].buffer = &db_prefix;
    // prefix_length output
    bind_out[2].buffer_type = MYSQL_TYPE_TINY;
    bind_out[2].is_unsigned = (my_bool)1;
    bind_out[2].buffer = &db_prefix_length;
    // prefix_max_length output
    bind_out[3].buffer_type = MYSQL_TYPE_TINY;
    bind_out[3].is_unsigned = (my_bool)1;
    bind_out[3].buffer = &db_prefix_max_length;
    // is_announce output
    bind_out[4].buffer_type = MYSQL_TYPE_TINY;
    bind_out[4].is_unsigned = (my_bool) 0;
    bind_out[4].buffer = &db_is_announce;

    if (mysql_stmt_bind_result(stmt, bind_out))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    // mysql_stmt_store_result is optional.  mysql_stmt_fetch will produce the
    // same data whether or not it is called.  But calling it brings the
    // whole result from the db at one time.
    if (mysql_stmt_store_result(stmt))
    {
        LOG(LOG_ERR, "mysql_stmt_store_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    while ((ret = mysql_stmt_fetch(stmt)) == 0)
    {
        if (fillPduIpPrefix(
            &((*_pdus)[*num_pdus]),
            db_asn,
            db_prefix, db_prefix_family_length,
            db_prefix_length, db_prefix_max_length,
            db_is_announce))
        {
            LOG(LOG_ERR, "could not create PDU_IPVx_PREFIX");
            mysql_stmt_free_result(stmt);
            return -1;
        }
        ++*num_pdus;

        state->first_row.first_time = 0;
        state->first_row.asn = db_asn;
        state->first_row.prefix_family_length = db_prefix_family_length;
        memcpy(state->first_row.prefix, db_prefix, db_prefix_family_length);
        state->first_row.prefix_length = db_prefix_length;
        state->first_row.prefix_max_length = db_prefix_max_length;
    }
    if (ret != 0 && ret != MYSQL_NO_DATA)
    {
        LOG(LOG_ERR, "error during mysql_stmt_fetch()");
        if (ret == 1)
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
                mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return -1;
    }

    mysql_stmt_free_result(stmt);

    return 0;
}


/**=============================================================================
------------------------------------------------------------------------------*/
static int serial_query_post_query(
    dbconn * conn,
    void *query_state,
    PDU ** _pdus,
    size_t * num_pdus,
    bool * is_done)
{
    struct query_state *state = (struct query_state *)query_state;
    int ret;

    uint32_t next_ser_num;
    uint32_t prev_ser_num;
    int prev_was_null = -1;

    *is_done = 1;

    // check whether sn is still valid
    ret = readSerNumAsCurrent(conn, state->ser_num,
                              1, &prev_ser_num, &prev_was_null, 0, NULL);
    if (ret == GET_SERNUM_ERR)
    {
        LOG(LOG_ERR, "error while checking validity of serial number");
        return -1;
    }
    else if (ret == GET_SERNUM_NONE || prev_was_null)
    {
        LOG(LOG_INFO, "serial number became invalid after creating PDUs");
        fill_pdu_error_report(&((*_pdus)[(*num_pdus)++]), ERR_NO_DATA, 0, NULL,
                              0, NULL);
        return 0;
    }

    // check whether to End or continue with next ser num
    ret = readSerNumAsPrev(conn, state->ser_num, 1, &next_ser_num);
    if (ret == GET_SERNUM_SUCCESS)
    {                           // db has sn for this sn_prev
        *is_done = 0;
        state->ser_num = next_ser_num;
        state->first_row.first_time = 1;
        return 0;
    }
    else if (ret == GET_SERNUM_NONE)
    {                           // db has no sn for this sn_prev
        LOG(LOG_DEBUG, "calling fill_pdu_end_of_data()");
        fill_pdu_end_of_data(&((*_pdus)[(*num_pdus)++]), state->session,
                             state->ser_num);
        return 0;
    }

    // NOTE: even though error, still feeding previous results,
    // which should be unaffected by this error.
    LOG(LOG_ERR,
        "error while looking for next serial number.  still sending pdus");
    LOG(LOG_DEBUG, "calling fill_pdu_end_of_data()");
    fill_pdu_end_of_data(&((*_pdus)[(*num_pdus)++]), state->session,
                         state->ser_num);
    return 0;
}


/**=============================================================================
 * @note see rtr.h about when to set is_done to 0 or 1.
 * @note If error, I call pdu_free_array(); else, caller does.
------------------------------------------------------------------------------*/
ssize_t db_rtr_serial_query_get_next(
    dbconn * conn,
    void *query_state,
    size_t max_rows,
    PDU ** _pdus,
    bool * is_done)
{
    PDU *pdus = NULL;
    struct query_state *state = (struct query_state *)query_state;
    size_t num_pdus = 0;
    int ret;

    *is_done = 1;

    pdus = calloc(max_rows, sizeof(PDU));
    if (!pdus)
    {
        LOG(LOG_ERR, "could not alloc for array of PDU");
        return -1;
    }
    *_pdus = pdus;

    if (!state->data_sent)
    {
        ret = serial_query_pre_query(conn, state, max_rows, _pdus, &num_pdus);
        if (ret == -1)
        {
            pdu_free_array(pdus, num_pdus);
            *_pdus = NULL;
            return -1;
        }
        else if (ret != 0)
        {
            return num_pdus;
        }
    }

    ret = serial_query_do_query(conn, state, max_rows, _pdus, &num_pdus);
    if (ret == -1)
    {
        pdu_free_array(*_pdus, num_pdus);
        *_pdus = NULL;
        return -1;
    }
    if (num_pdus == max_rows)
    {
        *is_done = 0;
        LOG(LOG_DEBUG, "returning %zu PDUs", num_pdus);
        return num_pdus;
    }

    ret = serial_query_post_query(conn, state, _pdus, &num_pdus, is_done);
    if (ret == -1)
    {
        pdu_free_array(*_pdus, num_pdus);
        *_pdus = NULL;
        return -1;
    }

    LOG(LOG_DEBUG, "returning %zu PDUs", num_pdus);
    return num_pdus;
}


/**=============================================================================
------------------------------------------------------------------------------*/
void db_rtr_serial_query_close(
    dbconn * conn,
    void *query_state)
{
    (void)conn;                 // to silence -Wunused-parameter
    free(query_state);
}


/**=============================================================================
------------------------------------------------------------------------------*/
int db_rtr_reset_query_init(
    dbconn * conn,
    void **query_state)
{
    struct query_state *state = NULL;
    int ret = 0;

    state = calloc(1, sizeof(struct query_state));
    if (!state)
    {
        LOG(LOG_ERR, "could not alloc for query_state");
        return -1;
    }
    state->ser_num = 0;
    state->first_row.first_time = 1;
    state->bad_ser_num = 0;
    state->data_sent = 0;
    state->no_new_data = 0;
    state->not_ready = 0;
    *query_state = (void *)state;

    ret = db_rtr_get_latest_sernum(conn, &state->ser_num);
    if (ret == GET_SERNUM_ERR)
    {
        if (state)
            free(state);
        *query_state = NULL;
        return -1;
    }
    else if (ret == GET_SERNUM_NONE)
    {
        state->not_ready = 1;
        return 0;
    }

    int has_full;
    ret = readSerNumAsCurrent(conn, state->ser_num, 0, NULL, NULL,
                              1, &has_full);
    if (ret != GET_SERNUM_SUCCESS)
    {
        if (state)
            free(state);
        *query_state = NULL;
        return -1;
    }
    if (!has_full)
    {
        LOG(LOG_ERR, "no has_full for latest serial number");
        state->not_ready = 1;
        return 0;
    }

    // data ready to send
    return 0;
}


/**=============================================================================
 * @note If error, I call pdu_free_array(); else, caller does.
------------------------------------------------------------------------------*/
ssize_t db_rtr_reset_query_get_next(
    dbconn * conn,
    void *query_state,
    size_t max_rows,
    PDU ** _pdus,
    bool * is_done)
{
    size_t num_pdus = 0;
    PDU *pdus = NULL;
    struct query_state *state = (struct query_state *)query_state;
    session_id_t session = 0;

    *is_done = 1;

    if (max_rows < 2)
    {
        LOG(LOG_ERR, "max_rows too small");
        return -1;
    }

    pdus = calloc(max_rows, sizeof(PDU));
    if (!pdus)
    {
        LOG(LOG_ERR, "could not alloc for array of PDU");
        return -1;
    }
    *_pdus = pdus;

    if (state->not_ready)
    {
        LOG(LOG_DEBUG, "no data is available to send to routers");
        fill_pdu_error_report(&((*_pdus)[num_pdus++]), ERR_NO_DATA, 0, NULL, 0,
                              NULL);
        LOG(LOG_DEBUG, "returning %zu PDUs", num_pdus);
        return num_pdus;
    }

    if (db_rtr_get_session_id(conn, &session))
    {
        LOG(LOG_ERR, "couldn't get session id");
        pdu_free_array(pdus, num_pdus);
        *_pdus = NULL;
        return -1;
    }

    if (!state->data_sent)
    {
        fill_pdu_cache_response(&((*_pdus)[num_pdus++]), session);
        state->data_sent = 1;
    }

    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_RESET_QRY_GET_NEXT];
    MYSQL_BIND bind_in[7];
    memset(bind_in, 0, sizeof(bind_in));
    // serial_num parameter
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].buffer = &(state->ser_num);
    bind_in[0].is_unsigned = (my_bool) 1;
    bind_in[0].is_null = (my_bool *) 0;
    // start-at-beginning parameter
    bind_in[1].buffer_type = MYSQL_TYPE_TINY;
    bind_in[1].buffer = &state->first_row.first_time;
    bind_in[1].is_unsigned = (my_bool)1;
    bind_in[1].is_null = (my_bool *)0;
    // asn parameter
    bind_in[2].buffer_type = MYSQL_TYPE_LONG;
    bind_in[2].buffer = &state->first_row.asn;
    bind_in[2].is_unsigned = (my_bool)1;
    bind_in[2].is_null = (my_bool *)0;
    // prefix parameter
    bind_in[3].buffer_type = MYSQL_TYPE_BLOB;
    bind_in[3].buffer = &state->first_row.prefix;
    bind_in[3].buffer_length = sizeof(state->first_row.prefix);
    unsigned long prefix_family_length;
    if (state->first_row.first_time)
    {
        prefix_family_length = 0;
    }
    else
    {
        prefix_family_length = state->first_row.prefix_family_length;
    }
    bind_in[3].length = &prefix_family_length;
    bind_in[3].is_null = (my_bool *)0;
    // prefix_length parameter
    bind_in[4].buffer_type = MYSQL_TYPE_TINY;
    bind_in[4].buffer = &state->first_row.prefix_length;
    bind_in[4].is_unsigned = (my_bool)1;
    bind_in[4].is_null = (my_bool *)0;
    // prefix_max_length parameter
    bind_in[5].buffer_type = MYSQL_TYPE_TINY;
    bind_in[5].buffer = &state->first_row.prefix_max_length;
    bind_in[5].is_unsigned = (my_bool)1;
    bind_in[5].is_null = (my_bool *)0;
    // limit parameter
    bind_in[6].buffer_type = MYSQL_TYPE_LONGLONG;
    unsigned long long limit = max_rows - num_pdus;
    bind_in[6].buffer = &limit;
    bind_in[6].is_unsigned = (my_bool) 1;
    bind_in[6].is_null = (my_bool *) 0;

    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        pdu_free_array(pdus, num_pdus);
        *_pdus = NULL;
        return -1;
    }

    if (wrap_mysql_stmt_execute
        (conn, stmt, "could not retrieve data from rtr_incremental"))
    {
        pdu_free_array(pdus, num_pdus);
        *_pdus = NULL;
        return -1;
    }

    MYSQL_BIND bind_out[4];
    unsigned db_asn;
    unsigned long db_prefix_family_length;
    unsigned char db_prefix[16];
    unsigned char db_prefix_length;
    unsigned char db_prefix_max_length;
    memset(bind_out, 0, sizeof(bind_out));
    // asn output
    bind_out[0].buffer_type = MYSQL_TYPE_LONG;
    bind_out[0].is_unsigned = 1;
    bind_out[0].buffer = &db_asn;
    // prefix output
    bind_out[1].buffer_type = MYSQL_TYPE_BLOB;
    bind_out[1].buffer_length = sizeof(db_prefix);
    bind_out[1].length = &db_prefix_family_length;
    bind_out[1].buffer = &db_prefix;
    // prefix_length output
    bind_out[2].buffer_type = MYSQL_TYPE_TINY;
    bind_out[2].is_unsigned = (my_bool)1;
    bind_out[2].buffer = &db_prefix_length;
    // prefix_max_length output
    bind_out[3].buffer_type = MYSQL_TYPE_TINY;
    bind_out[3].is_unsigned = (my_bool)1;
    bind_out[3].buffer = &db_prefix_max_length;

    if (mysql_stmt_bind_result(stmt, bind_out))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        pdu_free_array(pdus, num_pdus);
        *_pdus = NULL;
        return -1;
    }

    // mysql_stmt_store_result is optional.  mysql_stmt_fetch will produce the
    // same data whether or not it is called.  But calling it brings the
    // whole result from the db at one time.
    if (mysql_stmt_store_result(stmt))
    {
        LOG(LOG_ERR, "mysql_stmt_store_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        pdu_free_array(pdus, num_pdus);
        *_pdus = NULL;
        return -1;
    }

    int ret;
    while ((ret = mysql_stmt_fetch(stmt)) == 0)
    {
        if (fillPduIpPrefix(
            &((*_pdus)[num_pdus]),
            db_asn,
            db_prefix, db_prefix_family_length,
            db_prefix_length, db_prefix_max_length,
            1))
        {
            LOG(LOG_ERR, "could not create PDU_IPVx_PREFIX");
            mysql_stmt_free_result(stmt);
            pdu_free_array(pdus, num_pdus);
            *_pdus = NULL;
            return -1;
        }
        ++num_pdus;

        state->first_row.first_time = 0;
        state->first_row.asn = db_asn;
        state->first_row.prefix_family_length = db_prefix_family_length;
        memcpy(state->first_row.prefix, db_prefix, db_prefix_family_length);
        state->first_row.prefix_length = db_prefix_length;
        state->first_row.prefix_max_length = db_prefix_max_length;
    }
    if (ret != 0 && ret != MYSQL_NO_DATA)
    {
        LOG(LOG_ERR, "error during mysql_stmt_fetch()");
        if (ret == 1)
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
                mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        pdu_free_array(pdus, num_pdus);
        *_pdus = NULL;
        return -1;
    }

    if (num_pdus == max_rows)
    {
        mysql_stmt_free_result(stmt);
        *is_done = 0;
        LOG(LOG_DEBUG, "returning %zu PDUs", num_pdus);
        return num_pdus;
    }

    // See draft-ietf-sidr-rpki-rtr-19, section 5.4 Cache Response
    // Even if there is a newer sn, don't feed it.  rtr_incremental may
    // contain
    // a withdrawal, which must not be sent during a Cache Response.

    LOG(LOG_DEBUG, "calling fill_pdu_end_of_data()");
    fill_pdu_end_of_data(&((*_pdus)[num_pdus++]), session, state->ser_num);
    mysql_stmt_free_result(stmt);
    LOG(LOG_DEBUG, "returning %zu PDUs", num_pdus);
    return num_pdus;
}


/**=============================================================================
------------------------------------------------------------------------------*/
void db_rtr_reset_query_close(
    dbconn * conn,
    void *query_state)
{
    (void)conn;                 // to silence -Wunused-parameter
    free(query_state);
}

bool db_rtr_has_valid_session(
    dbconn * conn)
{
    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_COUNT_SESSION];
    int ret;

    if (wrap_mysql_stmt_execute(conn, stmt, NULL))
    {
        return false;
    }

    MYSQL_BIND bind_out[1];
    memset(bind_out, 0, sizeof(bind_out));
    unsigned long long session_count;
    bind_out[0].buffer_type = MYSQL_TYPE_LONGLONG;
    bind_out[0].is_unsigned = (my_bool)1;
    bind_out[0].buffer = &session_count;

    if (mysql_stmt_bind_result(stmt, bind_out))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return false;
    }

    if (mysql_stmt_store_result(stmt))
    {
        LOG(LOG_ERR, "mysql_stmt_store_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return false;
    }

    ret = mysql_stmt_fetch(stmt);
    if (ret != 0)
    {
        LOG(LOG_ERR, "mysql_stmt_fetch() failed");
        if (ret == 1)
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
                mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return false;
    }

    mysql_stmt_free_result(stmt);

    if (session_count == 0)
    {
        LOG(LOG_ERR, "The rpki-rtr database isn't initialized.");
        LOG(LOG_ERR, "See %s-rpki-rtr-initialize.", PACKAGE_NAME);
        return false;
    }
    else if (session_count != 1)
    {
        LOG(LOG_ERR,
            "The rtr_session table has %llu "
            "entries, which should never happen.",
            session_count);
        LOG(LOG_ERR,
            "Consider running %s-rpki-rtr-clear and %s-rpki-rtr-initialize.",
            PACKAGE_NAME, PACKAGE_NAME);
        return false;
    }
    else
    {
        return true;
    }
}

bool db_rtr_delete_incomplete_updates(
    dbconn * conn)
{
    return
        !wrap_mysql_stmt_execute(
            conn,
            conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_DELETE_INCOMPLETE_INCREMENTAL],
            NULL)
            &&
        !wrap_mysql_stmt_execute(
            conn,
            conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_DELETE_INCOMPLETE_FULL],
            NULL)
            ;
}

bool db_rtr_good_serials(
    dbconn * conn,
    serial_number_t previous,
    serial_number_t current)
{
    int ret;

    // Convert previous and current to a type that MySQL can take.
    COMPILE_TIME_ASSERT(
        TYPE_CAN_HOLD_UINT(unsigned, serial_number_t));
    unsigned previous_uint = previous;
    unsigned current_uint = current;

    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_DETECT_INCONSISTENT_STATE];
    MYSQL_BIND bind_in[3];
    memset(bind_in, 0, sizeof(bind_in));
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].buffer = &current_uint;
    bind_in[0].is_unsigned = (my_bool)1;
    bind_in[0].is_null = (my_bool *)0;
    bind_in[1].buffer_type = MYSQL_TYPE_LONG;
    bind_in[1].buffer = &current_uint;
    bind_in[1].is_unsigned = (my_bool)1;
    bind_in[1].is_null = (my_bool *)0;
    bind_in[2].buffer_type = MYSQL_TYPE_LONG;
    bind_in[2].buffer = &previous_uint;
    bind_in[2].is_unsigned = (my_bool)1;
    bind_in[2].is_null = (my_bool *)0;

    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        return false;
    }

    if (wrap_mysql_stmt_execute(conn, stmt, NULL))
    {
        return false;
    }

    MYSQL_BIND bind_out[1];
    unsigned char is_inconsistent;
    memset(bind_out, 0, sizeof(bind_out));
    bind_out[0].buffer_type = MYSQL_TYPE_TINY;
    bind_out[0].is_unsigned = 1;
    bind_out[0].buffer = &is_inconsistent;

    if (mysql_stmt_bind_result(stmt, bind_out))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return false;
    }

    ret = mysql_stmt_fetch(stmt);
    if (ret != 0)
    {
        LOG(LOG_ERR, "mysql_stmt_fetch() failed");
        if (ret == 1)
            LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
                mysql_stmt_error(stmt));
        mysql_stmt_free_result(stmt);
        return false;
    }

    mysql_stmt_free_result(stmt);

    return !is_inconsistent;
}

bool db_rtr_insert_full(
    dbconn * conn,
    serial_number_t serial)
{
    struct flag_tests flag_tests;
    flag_tests_default(&flag_tests);

    // Convert serial to a type that MySQL can take.
    COMPILE_TIME_ASSERT(
        TYPE_CAN_HOLD_UINT(unsigned, serial_number_t));
    unsigned serial_uint = serial;

    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_INSERT_FULL];
    MYSQL_BIND bind_in[1 + FLAG_TESTS_PARAMETERS];
    memset(bind_in, 0, sizeof(bind_in));
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].buffer = &serial_uint;
    bind_in[0].is_unsigned = (my_bool)1;
    bind_in[0].is_null = (my_bool *)0;
    flag_tests_bind(bind_in + 1, &flag_tests);

    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        return false;
    }

    if (wrap_mysql_stmt_execute(conn, stmt, NULL))
    {
        return false;
    }

    return true;
}

bool db_rtr_insert_incremental(
    dbconn * conn,
    serial_number_t previous_serial,
    serial_number_t current_serial)
{
    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_INSERT_INCREMENTAL];
    MYSQL_BIND bind_in[4];

    // Convert previous_serial and current_serial to a type that MySQL
    // can take.
    COMPILE_TIME_ASSERT(
        TYPE_CAN_HOLD_UINT(unsigned, serial_number_t));
    unsigned previous_serial_uint = previous_serial;
    unsigned current_serial_uint = current_serial;

    unsigned char is_announce;

    // announcements
    memset(bind_in, 0, sizeof(bind_in));
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].buffer = &current_serial_uint;
    bind_in[0].is_unsigned = (my_bool)1;
    bind_in[0].is_null = (my_bool *)0;
    is_announce = 1;
    bind_in[1].buffer_type = MYSQL_TYPE_TINY;
    bind_in[1].buffer = &is_announce;
    bind_in[1].is_unsigned = (my_bool)1;
    bind_in[1].is_null = (my_bool *)0;
    bind_in[2].buffer_type = MYSQL_TYPE_LONG;
    bind_in[2].buffer = &previous_serial_uint;
    bind_in[2].is_unsigned = (my_bool)1;
    bind_in[2].is_null = (my_bool *)0;
    bind_in[3].buffer_type = MYSQL_TYPE_LONG;
    bind_in[3].buffer = &current_serial_uint;
    bind_in[3].is_unsigned = (my_bool)1;
    bind_in[3].is_null = (my_bool *)0;

    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        return false;
    }

    if (wrap_mysql_stmt_execute(conn, stmt, NULL))
    {
        return false;
    }

    // withdrawals
    memset(bind_in, 0, sizeof(bind_in));
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].buffer = &current_serial_uint;
    bind_in[0].is_unsigned = (my_bool)1;
    bind_in[0].is_null = (my_bool *)0;
    is_announce = 0;
    bind_in[1].buffer_type = MYSQL_TYPE_TINY;
    bind_in[1].buffer = &is_announce;
    bind_in[1].is_unsigned = (my_bool)1;
    bind_in[1].is_null = (my_bool *)0;
    bind_in[2].buffer_type = MYSQL_TYPE_LONG;
    bind_in[2].buffer = &current_serial_uint;
    bind_in[2].is_unsigned = (my_bool)1;
    bind_in[2].is_null = (my_bool *)0;
    bind_in[3].buffer_type = MYSQL_TYPE_LONG;
    bind_in[3].buffer = &previous_serial_uint;
    bind_in[3].is_unsigned = (my_bool)1;
    bind_in[3].is_null = (my_bool *)0;

    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        return false;
    }

    if (wrap_mysql_stmt_execute(conn, stmt, NULL))
    {
        return false;
    }

    return true;
}

int db_rtr_has_incremental_changes(
    dbconn * conn,
    serial_number_t serial)
{
    int ret;

    // Convert serial to a type that MySQL can take.
    COMPILE_TIME_ASSERT(
        TYPE_CAN_HOLD_UINT(unsigned, serial_number_t));
    unsigned serial_uint = serial;

    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_HAS_CHANGES];
    MYSQL_BIND bind_in[1];
    memset(bind_in, 0, sizeof(bind_in));
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].buffer = &serial_uint;
    bind_in[0].is_unsigned = (my_bool)1;
    bind_in[0].is_null = (my_bool *)0;

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

    MYSQL_BIND bind_out[1];
    memset(bind_out, 0, sizeof(bind_out));
    unsigned char has_changes = 0;
    bind_out[0].buffer_type = MYSQL_TYPE_TINY;
    bind_out[0].buffer = &has_changes;
    bind_out[0].is_unsigned = (my_bool)1;

    if (mysql_stmt_bind_result(stmt, bind_out))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_result() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
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

    mysql_stmt_free_result(stmt);

    if (has_changes)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

bool db_rtr_insert_update(
    dbconn * conn,
    serial_number_t current_serial,
    serial_number_t previous_serial,
    bool previous_serial_is_null)
{
    // Convert previous_serial and current_serial to a type that MySQL
    // can take.
    COMPILE_TIME_ASSERT(
        TYPE_CAN_HOLD_UINT(unsigned, serial_number_t));
    unsigned previous_serial_uint = previous_serial;
    unsigned current_serial_uint = current_serial;

    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_INSERT_UPDATE];
    MYSQL_BIND bind_in[2];
    memset(bind_in, 0, sizeof(bind_in));
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].buffer = &current_serial_uint;
    bind_in[0].is_unsigned = (my_bool)1;
    bind_in[0].is_null = (my_bool *)0;
    my_bool my_previous_serial_is_null =
        (my_bool)previous_serial_is_null;
    bind_in[1].buffer_type = MYSQL_TYPE_LONG;
    bind_in[1].buffer = &previous_serial_uint;
    bind_in[1].is_unsigned = (my_bool)1;
    bind_in[1].is_null = &my_previous_serial_is_null;

    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        return false;
    }

    if (wrap_mysql_stmt_execute(conn, stmt, NULL))
    {
        return false;
    }

    return true;
}

bool db_rtr_delete_full(
    dbconn * conn,
    serial_number_t serial)
{
    // Convert serial to a type that MySQL can take.
    COMPILE_TIME_ASSERT(
        TYPE_CAN_HOLD_UINT(unsigned, serial_number_t));
    unsigned serial_uint = serial;

    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_DELETE_USELESS_FULL];
    MYSQL_BIND bind_in[1];
    memset(bind_in, 0, sizeof(bind_in));
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].buffer = &serial_uint;
    bind_in[0].is_unsigned = (my_bool)1;
    bind_in[0].is_null = (my_bool *)0;

    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        return false;
    }

    if (wrap_mysql_stmt_execute(conn, stmt, NULL))
    {
        return false;
    }

    return true;
}

bool db_rtr_ignore_old_full(
    dbconn * conn,
    serial_number_t serial1,
    serial_number_t serial2)
{
    // Convert serial1 and serial2 to a type that MySQL can take.
    COMPILE_TIME_ASSERT(
        TYPE_CAN_HOLD_UINT(unsigned, serial_number_t));
    unsigned serial1_uint = serial1;
    unsigned serial2_uint = serial2;

    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_IGNORE_OLD_FULL];
    MYSQL_BIND bind_in[2];
    memset(bind_in, 0, sizeof(bind_in));
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].buffer = &serial1_uint;
    bind_in[0].is_unsigned = (my_bool)1;
    bind_in[0].is_null = (my_bool *)0;
    bind_in[1].buffer_type = MYSQL_TYPE_LONG;
    bind_in[1].buffer = &serial2_uint;
    bind_in[1].is_unsigned = (my_bool)1;
    bind_in[1].is_null = (my_bool *)0;

    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        return false;
    }

    if (wrap_mysql_stmt_execute(conn, stmt, NULL))
    {
        return false;
    }

    return true;
}

bool db_rtr_delete_old_full(
    dbconn * conn,
    serial_number_t serial1,
    serial_number_t serial2)
{
    // Convert serial1 and serial2 to a type that MySQL can take.
    COMPILE_TIME_ASSERT(
        TYPE_CAN_HOLD_UINT(unsigned, serial_number_t));
    unsigned serial1_uint = serial1;
    unsigned serial2_uint = serial2;

    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_DELETE_OLD_FULL];
    MYSQL_BIND bind_in[2];
    memset(bind_in, 0, sizeof(bind_in));
    bind_in[0].buffer_type = MYSQL_TYPE_LONG;
    bind_in[0].buffer = &serial1_uint;
    bind_in[0].is_unsigned = (my_bool)1;
    bind_in[0].is_null = (my_bool *)0;
    bind_in[1].buffer_type = MYSQL_TYPE_LONG;
    bind_in[1].buffer = &serial2_uint;
    bind_in[1].is_unsigned = (my_bool)1;
    bind_in[1].is_null = (my_bool *)0;

    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        return false;
    }

    if (wrap_mysql_stmt_execute(conn, stmt, NULL))
    {
        return false;
    }

    return true;
}

bool db_rtr_delete_old_update(
    dbconn * conn,
    serial_number_t serial1,
    serial_number_t serial2)
{
    // Convert serial1 and serial2 to a type that MySQL can take.
    COMPILE_TIME_ASSERT(
        TYPE_CAN_HOLD_UINT(unsigned, serial_number_t));
    unsigned serial1_uint = serial1;
    unsigned serial2_uint = serial2;

    long long retention_hours =
        (long long)CONFIG_RPKI_RTR_RETENTION_HOURS_get();

    MYSQL_STMT *stmt =
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_DELETE_OLD_UPDATE];
    MYSQL_BIND bind_in[3];
    memset(bind_in, 0, sizeof(bind_in));
    bind_in[0].buffer_type = MYSQL_TYPE_LONGLONG;
    bind_in[0].buffer = &retention_hours;
    bind_in[0].is_unsigned = (my_bool)0;
    bind_in[0].is_null = (my_bool *)0;
    bind_in[1].buffer_type = MYSQL_TYPE_LONG;
    bind_in[1].buffer = &serial1_uint;
    bind_in[1].is_unsigned = (my_bool)1;
    bind_in[1].is_null = (my_bool *)0;
    bind_in[2].buffer_type = MYSQL_TYPE_LONG;
    bind_in[2].buffer = &serial2_uint;
    bind_in[2].is_unsigned = (my_bool)1;
    bind_in[2].is_null = (my_bool *)0;

    if (mysql_stmt_bind_param(stmt, bind_in))
    {
        LOG(LOG_ERR, "mysql_stmt_bind_param() failed");
        LOG(LOG_ERR, "    %u: %s\n", mysql_stmt_errno(stmt),
            mysql_stmt_error(stmt));
        return false;
    }

    if (wrap_mysql_stmt_execute(conn, stmt, NULL))
    {
        return false;
    }

    return true;
}

bool db_rtr_ignore_old_incremental(
    dbconn * conn)
{
    return !wrap_mysql_stmt_execute(
        conn,
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_IGNORE_OLD_INCREMENTAL],
        NULL);
}

bool db_rtr_delete_old_incremental(
    dbconn * conn)
{
    return !wrap_mysql_stmt_execute(
        conn,
        conn->stmts[DB_CLIENT_TYPE_RTR][DB_PSTMT_RTR_DELETE_OLD_INCREMENTAL],
        NULL);
}
