/**
	Functions used for accessing the RTR database.
*/

#ifndef _UTILS_MYSQL_RTR_H
#define _UTILS_MYSQL_RTR_H

#include <stdbool.h>

#include "pdu.h"


struct query_state;
//struct _query_state;
//typedef struct _query_state query_state;


// <cache_state>
int getCacheNonce(void *connp, cache_nonce_t * nonce);
// </cache_state>


#define GET_SERNUM_SUCCESS 0  // success, returning latest ser num
#define GET_SERNUM_ERROR  -1  // some undefined error
#define GET_SERNUM_NONE   -2  // no error, but db contains no ser nums
int getLatestSerialNumber(void *connp, serial_number_t * serial);


#define VAL_SERNUM_IS_PREV    0  // sn in db.rtr_update.prev_serial_num
#define VAL_SERNUM_DATA_INCR  1  // sn in db.rtr_update.serial_num
#define VAL_SERNUM_DATA_FULL  2  // sn in db.rtr_update.serial_num and has_full
#define VAL_SERNUM_ERR       -1  // some undefined error
int isValidSerNumPrev(void *connp, uint32_t sn);
int isValidSerNumData(void *connp, uint32_t sn);


// <db>
/**
	@param query_state A return parameter for an opaque data type that
		stores the information needed by serialQueryGetNext() to
		return the next set of rows.
	@param serial The serial number to start the query after.
	@return 0 on success or an error code on failure.
*/
int startSerialQuery(void *connp, void ** query_state, serial_number_t serial);

/**
	@param query_state A query state returned by startSerialQuery().
		This structure is updated with each call to serialQueryGetNext()
		so that subsequent calls don't return the same data.
	@param num_rows The maximum number of rows to fetch.
	@param pdus A return parameter for an array of PDUs with the results.
		This array must be free()d with pdu_free_array() when it's no longer needed.
		On the first call to serialQueryGetNext(), this array must start with
		a Cache Response, Cache Reset, or Error Report PDU as appropriate.
		If is_done is set to true or an error code is returned,
		this array must end with either an End of Data or Error Report PDU.
	@param is_done A return parameter for whether the query finished or not.
	@return A nonnegative number of rows returned on success,
		or a negative error code on failure. Zero is returned only
		if is_done is set to true, but note that is_done may be true
		for any return value and must be true for any fatal error
		code.
*/
ssize_t serialQueryGetNext(void *connp, void * query_state, size_t max_rows,
	PDU ** _pdus, bool * is_done);

/**
	Free any resources needed. This must be called when the calling
	program is done with a query. This may be called when query_state
	is in any state, e.g. before ever calling serialQueryGetNext(),
	after calling serialQueryGetNext() but before it returns with is_done
	set to true, or after any cancelation point in serialQueryGetNext().
*/
void stopSerialQuery(void *connp, void * query_state);

// see the equivalent functions for serial queries above for descriptions
// of parameters and return values
int startResetQuery(void *connp, void ** query_state);

ssize_t resetQueryGetNext(void *connp, void * query_state, size_t max_rows,
	PDU ** pdus, bool * is_done);

void stopResetQuery(void *connp, void * query_state);
// </db>

int parseIpaddr(uint *family, struct in_addr *addr4, struct in6_addr *addr6,
        uint *prefix_len, uint *max_len, const char field_str[]);


#endif
