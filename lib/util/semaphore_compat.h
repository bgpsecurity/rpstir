#ifndef _UTILS_SEMAPHORE_COMPAT_H
#define _UTILS_SEMAPHORE_COMPAT_H

#include <semaphore.h>

#ifndef HAVE_SEM_TIMEDWAIT
// Before use, see surgeon general's warning in semaphore_compat.c
int sem_timedwait(
    sem_t * sem,
    const struct timespec *abs_timeout);
#endif


/**
    Create an unnamed semaphore if possible. Otherwise, create a named
    semaphore.

    NOTE: This function is only tested for pshared=0. It might not work right
          with non-zero values of pshared.

    @param pshared If unnamed semaphores are supported, this parameter is
                   passed directly to sem_init. Otherwise, it's ignored.
    @param value Initial value for the semaphore.
    @return On success, a new semaphore. On failure, SEM_FAILED is returned
            and errno is set.
*/
sem_t * semcompat_new(
    int pshared,
    unsigned int value);

/**
    Free any resources used by a semaphore returned by semcompat_new.

    @return On success, zero. On failure, -1 is returned and errno is set.
*/
int semcompat_free(
    sem_t * sem);

#endif
