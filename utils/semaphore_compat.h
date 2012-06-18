#ifndef _UTILS_SEMAPHORE_COMPAT_H
#define _UTILS_SEMAPHORE_COMPAT_H

#include <semaphore.h>

#ifndef HAVE_SEM_TIMEDWAIT
// Before use, see surgeon general's warning in semaphore_compat.c
int sem_timedwait(
    sem_t * sem,
    const struct timespec *abs_timeout);
#endif

#endif
