#ifndef _RTR_CONNECTION_CONTROL_H
#define _RTR_CONNECTION_CONTROL_H

// Declarations related to the connection control thread.
// Currently: main entry point and related arguments.

#include "db.h"

// memory is handled entirely by main
struct connection_control_main_args {
    const int *listen_fds;
    size_t num_listen_fds;
    Queue *db_request_queue;
    db_semaphore_t *db_semaphore;
    struct global_cache_state *global_cache_state;
};
void *connection_control_main(
    void *args_voidp);

#endif
