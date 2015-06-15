/**
	Functions used for accessing the RTR database.
*/

#ifndef _UTILS_MYSQL_RTR_H
#define _UTILS_MYSQL_RTR_H

#include <stdbool.h>

#include "db/connect.h"
#include "rpki-rtr/pdu.h"


int db_rtr_get_session_id(
    dbconn * conn,
    session_id_t * session);


#define GET_SERNUM_SUCCESS 0
#define GET_SERNUM_ERR -1
#define GET_SERNUM_NONE -2
int db_rtr_get_latest_sernum(
    dbconn * conn,
    serial_number_t * serial);


/**
	@param query_state A return parameter for an opaque data type that
		stores the information needed by serialQueryGetNext() to
		return the next set of rows.
	@param serial The serial number to start the query after.
	@return 0 on success or an error code on failure.
*/
int db_rtr_serial_query_init(
    dbconn * conn,
    void **query_state,
    serial_number_t serial);

/**
	@param query_state A query state returned by startSerialQuery().
		This structure is updated with each call to serialQueryGetNext()
		so that subsequent calls don't return the same data.
	@param num_rows The maximum number of rows to fetch.
	    The number of PDUs returned are allowed to exceed this.
	@param pdus A return parameter for an array of PDUs with the results.
		This is only filled in if the function returns a postive number.
		The rest of this paragraph only applies when this function returns a nonnegative number.
		This array must be free()d with pdu_free_array() when it's no longer needed.
		On the first successful call to serialQueryGetNext(), this array must
		start with a Cache Response, Cache Reset, or Error Report PDU as appropriate.
		If is_done is set to true, this must end with a PDU that the client
		will understand to indicate the end of a response, such as Error Report
		or End of Data. Note that if the function returns 1, the previous two
		sentences can refer to the same PDU.
	@param is_done A return parameter for whether the query finished or not.
	@return A nonnegative number of PDUs returned on success,
		or a negative error code on failure. Zero is returned only
		if is_done is set to true, but note that is_done may be true
		for any return value and must be true for any error code.
*/
ssize_t db_rtr_serial_query_get_next(
    dbconn * conn,
    void *query_state,
    size_t max_rows,
    PDU ** _pdus,
    bool * is_done);

/**
	Free any resources needed. This must be called when the calling
	program is done with a query. This may be called when query_state
	is in any state, e.g. before ever calling serialQueryGetNext(),
	after calling serialQueryGetNext() but before it returns with is_done
	set to true, or after any cancelation point in serialQueryGetNext().
*/
void db_rtr_serial_query_close(
    dbconn * conn,
    void *query_state);

// see the equivalent functions for serial queries above for descriptions
// of parameters and return values
int db_rtr_reset_query_init(
    dbconn * conn,
    void **query_state);

ssize_t db_rtr_reset_query_get_next(
    dbconn * conn,
    void *query_state,
    size_t max_rows,
    PDU ** _pdus,
    bool * is_done);

void db_rtr_reset_query_close(
    dbconn * conn,
    void *query_state);

/**
    @brief Determine if there's a valid rpki-rtr session.
*/
bool db_rtr_has_valid_session(
    dbconn * conn);

/**
    @brief Delete incomplete updates.

    @return True on success, false on failure.
*/
bool db_rtr_delete_incomplete_updates(
    dbconn * conn);

/**
    @brief Detect if using the given serial numbers would put the
        database into a weird or inconsistent state.

    @return True if the serial numbers are ok to use, false if they're
        not or there was an error.
*/
bool db_rtr_good_serials(
    dbconn * conn,
    serial_number_t previous,
    serial_number_t current);

/**
    @brief Copy the current state of the RPKI cache to the rtr_full
        table, using the given serial number.

    @return True on success, false on failure.
*/
bool db_rtr_insert_full(
    dbconn * conn,
    serial_number_t serial);

/**
    @brief Compute the incremental changes from previous_serial to
        current_serial.

    @return True on success, false on failure.
*/
bool db_rtr_insert_incremental(
    dbconn * conn,
    serial_number_t previous_serial,
    serial_number_t current_serial);

/**
    @brief Determine if the serial number has any changes from the
        serial before it.

    @return If there are any changes, 1. If there are no changes, 0.
        If there's an error, -1.
*/
int db_rtr_has_incremental_changes(
    dbconn * conn,
    serial_number_t serial);

/**
    @brief Mark an update as available.

    @param[in] conn DB connection.
    @param[in] current_serial Current serial number for the update.
    @param[in] previous_serial Serial number for the previous update.
        This is ignored if @p previous_serial_is_null.
    @param[in] previous_serial_is_null Whether or not there was a
        previous update.
    @return True on success, false on failure.
*/
bool db_rtr_insert_update(
    dbconn * conn,
    serial_number_t current_serial,
    serial_number_t previous_serial,
    bool previous_serial_is_null);

/**
    @brief Delete the rtr_full data for a single serial number.

    @return True on success, false on failure.
*/
bool db_rtr_delete_full(
    dbconn * conn,
    serial_number_t serial);

/**
    @brief Mark full data for serials other than serial1 or serial2
        as unavailable.

    @return True on success, false on failure.
*/
bool db_rtr_ignore_old_full(
    dbconn * conn,
    serial_number_t serial1,
    serial_number_t serial2);

/**
    @brief Delete full data for serials other than serial1 or serial2.

    @return True on success, false on failure.
*/
bool db_rtr_delete_old_full(
    dbconn * conn,
    serial_number_t serial1,
    serial_number_t serial2);

/**
    @brief Mark updates older than the configured interval as
        unavailable, with the exception that serial1 and serial2
        are not marked unavailable regardless of age.

    @return True on success, false on failure.
*/
bool db_rtr_delete_old_update(
    dbconn * conn,
    serial_number_t serial1,
    serial_number_t serial2);

/**
    @brief Mark incremental data unavailable if the previous serial
        is already unavailable.

    @return True on success, false on failure.
*/
bool db_rtr_ignore_old_incremental(
    dbconn * conn);

/**
    @brief Delete any incremental data that's no longer available.

    @return True on success, false on failure.
*/
bool db_rtr_delete_old_incremental(
    dbconn * conn);


#endif
