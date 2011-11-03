#ifndef _RTR_DB_H
#define _RTR_DB_H

#include <semaphore.h>

#include "queue.h"

#include "pdu.h"
#include "connection.h"


typedef sem_t db_semaphore_t;

struct db_query; // TODO
struct db_query_progress; // TODO

struct db_request {
	struct db_query query;
	Queue * response_queue;
	cxn_semaphore_t * response_semaphore;
};

struct db_response {
	PDU * PDUs;
	bool is_done;
	db_semaphore_t * more_data_semaphore;
};

#endif
