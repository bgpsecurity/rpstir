#ifndef _RTR_CONNECTION_H
#define _RTR_CONNECTION_H

#include <semaphore.h>

typedef sem_t cxn_semaphore_t;

enum cxn_state {READY, RUNNING};

#endif
