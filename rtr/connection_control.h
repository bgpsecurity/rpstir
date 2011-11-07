#ifndef _RTR_CONNECTION_CONTROL_H
#define _RTR_CONNECTION_CONTROL_H

#include "db.h"

struct connection_control_main_args {
	int listen_fd;
	Queue * db_request_queue;
	Bag * db_semaphores_all;
	struct global_cache_state * global_cache_state;
};
void * connection_control_main(void * args_voidp);

#endif
