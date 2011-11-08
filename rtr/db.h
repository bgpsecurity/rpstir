#ifndef _RTR_DB_H
#define _RTR_DB_H

#include <semaphore.h>

#include "queue.h"
#include "bag.h"

#include "pdu.h"
#include "connection.h"


typedef sem_t db_semaphore_t;

struct db_query {
	enum { SERIAL_QUERY, RESET_QUERY } type;
	union {
		struct {
			cache_nonce_t nonce;
			serial_number_t serial;
		} serial_query;
		struct {
		} reset_query;
	};
};

// The below should work for a query like SELECT ... FROM ... WHERE serial = last_serial ORDER BY ... LIMIT last_row, ...
struct db_query_progress {
	serial_number_t last_serial;
	size_t last_row;
};

struct db_request {
	struct db_query query;
	Queue * response_queue;
	cxn_semaphore_t * response_semaphore;
};

struct db_response {
	PDU * PDUs;
	size_t num_PDUs;
	db_semaphore_t * more_data_semaphore;
};

struct db_main_args {
	db_semaphore_t * semaphore;
	Queue * db_request_queue;
};
void * db_main(void * args_voidp);

#endif
