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
			serial_number_t serial;
		} serial_query;
		struct {
		} reset_query;
	};
};

// memory is handled entirely by cxn threads, db threads must not free() these
struct db_request {
	struct db_query query;
	Queue * response_queue;
	cxn_semaphore_t * response_semaphore;
	volatile bool cancel_request; // the cxn thread can set this to true to cancel a request
};

// memory is allocated by db threads and free()ed by cxn threads
struct db_response {
	PDU * PDUs;
	size_t num_PDUs;
	db_semaphore_t * more_data_semaphore; // this is not free()ed or destroyed by the cxn thread
};

struct db_main_args {
	db_semaphore_t * semaphore;
	Queue * db_request_queue;
};
void * db_main(void * args_voidp);

#endif
