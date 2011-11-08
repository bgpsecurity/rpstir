#ifndef _RTR_CONNECTION_H
#define _RTR_CONNECTION_H

#include <semaphore.h>

#include "bag.h"
#include "queue.h"

#include "cache_state.h"

typedef sem_t cxn_semaphore_t;

struct connection_main_args {
	int socket;
	cxn_semaphore_t * semaphore;
	Queue * db_request_queue;
	Bag * db_semaphores_all;
	struct global_cache_state * global_cache_state;
};
void * connection_main(void * args_voidp);

#endif
