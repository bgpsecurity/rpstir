#ifndef _RTR_CONNECTION_H
#define _RTR_CONNECTION_H

#include "bag.h"
#include "queue.h"

#include "cache_state.h"
#include "semaphores.h"


// memory is alocated by connection_control and free()d by connection
struct connection_main_args {
	int socket;
	cxn_semaphore_t * semaphore;
	Queue * db_request_queue;
	db_semaphore_t * db_semaphore;
	struct global_cache_state * global_cache_state;
};
void * connection_main(void * args_voidp);

#endif
