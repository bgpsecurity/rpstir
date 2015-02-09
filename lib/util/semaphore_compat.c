#include "semaphore_compat.h"

#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>
#include <fcntl.h>

#include "util/logging.h"

#define SEM_OPEN_MAX_TRIES 256

/*
 * OpenBSD lacks sem_timedwait(), so we implement a simple version here.  This
 * function is sufficient for the RTR server implementation because threads
 * call this only when they are waiting with nothing to do.  In addition, for
 * the RTR server, the max number of threads waiting on each semaphore is
 * anticipated to be 1.
 *
 * Warning: this function may have limitations when compared to a standard
 * implementation of sem_timedwait().
 *
 * According to Tanenbaum in _Modern Operating Systems_, critical regions
 * should be designed to obey the following four conditions:
 *
 * 1. (Mutal Exclusion) No two processes may be simultaneously inside their
 *    critical regions.
 * 2. No assumptions may be made about speeds or the number
 *    of CPUs.
 * 3. (Progress) No process running outside its critical region may
 *    block other processes.
 * 4. (Bounded wait) No process should have to wait forever to enter its
 *    critical region.
 *
 * Warning: this function does NOT ensure #4 (Bounded wait).  Also, this is
 * minor, but in the unlikely event that nanosleep() fails repeatedly and we
 * spin, there could be a soft violation of #3 (Progress) due to priority
 * inversion.
 */

#ifndef HAVE_SEM_TIMEDWAIT
int sem_timedwait(
    sem_t * sem,
    const struct timespec *abs_timeout)
{
    int retval;
    int sem_errno;
    struct timespec now;
    static const struct timespec sleep_interval = { 0, 100000000L };

    while (true)
    {
        pthread_testcancel();

        retval = sem_trywait(sem);
        if (retval == 0)
        {
            return 0;
        }

        sem_errno = errno;

        if (sem_errno != EAGAIN)
            break;

        if (abs_timeout->tv_nsec < 0 || abs_timeout->tv_nsec >= 1000000000L)
        {
            sem_errno = EINVAL;
            break;
        }

        #ifdef HAVE_CLOCK_GETTIME
        if (clock_gettime(CLOCK_REALTIME, &now) != 0)
        {
            // unfortunately none of the valid errors for sem_timedwait
            // actually match
            // this error, but EINVAL seems the closest
            sem_errno = EINVAL;
            break;
        }
        #else
        now.tv_sec = time(NULL);
        now.tv_nsec = 0L;
        #endif

        if (now.tv_sec > abs_timeout->tv_sec
            || (now.tv_sec == abs_timeout->tv_sec
                && now.tv_nsec >= abs_timeout->tv_nsec))
        {
            sem_errno = ETIMEDOUT;
            break;
        }

        // Ignore the return value because if nanosleep() doesn't work
        // it's best to just spin.
        nanosleep(&sleep_interval, NULL);
    }

    errno = sem_errno;
    return retval;
}
#endif


static pthread_once_t support_unnamed_initialized = PTHREAD_ONCE_INIT;
static bool support_unnamed;

/** Test wether unnamed semaphores are supported. */
static void initialize_support_unnamed()
{
    char errorbuf[ERROR_BUF_SIZE];
    sem_t test_sem;

    if (sem_init(&test_sem, 0, 0) == 0)
    {
        support_unnamed = true;

        if (sem_destroy(&test_sem) != 0)
        {
            ERR_LOG(errno, errorbuf, "sem_destroy()");
        }
    }
    else
    {
        switch (errno)
        {
            case ENOSYS:
                support_unnamed = false;
                break;

            default:
                // It /might/ be a temporary error, so just log it and move on.
                ERR_LOG(errno, errorbuf, "sem_init()");
                support_unnamed = true;
                break;
        }
    }

    if (support_unnamed)
    {
        LOG(LOG_DEBUG, "system appears to support unnamed semaphores");
    }
    else
    {
        LOG(LOG_DEBUG, "system does not appear to support unnamed semaphores");
    }
}

/**
    Size of a buffer to hold a NULL-terminated semaphore name. See
    http://www.daemon-systems.org/man/sem_open.3.html for the choice of value.
*/
#define SEM_NAME_SIZE 14

#define SEM_NAME_ALPHABET "abcdefghijklmnopqrstuvqxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

/**
    Create a pseudo-random name for a semaphore.

    XXX: The names this generates are probably predictable. This opens up two
    classes of attacks:

    Local, unprivileged user: It may be possible to cause a denial of service by
    creating SEM_OPEN_MAX_TRIES semaphores with appropriate names. This can be
    mitigated by banning that user.

    Local, privileged user (root, or the same user that's running the process
    that calls semcompat_new): It may be possible to open a named semaphore
    after we open it and before we unlink it. This could cause unexpected
    behavior. However, a privileged user can generally do much worse anyway.
*/
static void make_sem_name(
    char buf[SEM_NAME_SIZE])
{
    size_t i;

    buf[0] = '/';

    for (i = 1; i < SEM_NAME_SIZE - 1; ++i)
    {
        // In general, this is not a uniform distribution, but it should be
        // close enough.
        buf[i] = SEM_NAME_ALPHABET[random() % (sizeof(SEM_NAME_ALPHABET) - 1)];
    }

    buf[SEM_NAME_SIZE - 1] = '\0';
}

sem_t * semcompat_new(
    int pshared,
    unsigned int value)
{
    sem_t * ret;
    int errno_save;

    if (pthread_once(&support_unnamed_initialized, initialize_support_unnamed) != 0)
    {
        // errno is set by pthread_once
        return SEM_FAILED;
    }

    if (support_unnamed)
    {
        ret = malloc(sizeof(sem_t));
        if (ret == NULL)
        {
            // errno is set by malloc
            return SEM_FAILED;
        }

        if (sem_init(ret, pshared, value) != 0)
        {
            errno_save = errno;
            free(ret);
            errno = errno_save;
            return SEM_FAILED;
        }

        return ret;
    }
    else
    {
        size_t i;
        char name[SEM_NAME_SIZE];

        for (i = 0; i < SEM_OPEN_MAX_TRIES; ++i)
        {
            make_sem_name(name);

            ret = sem_open(name, O_CREAT | O_EXCL, 0600, value);
            if (ret == SEM_FAILED)
            {
                if (errno == EEXIST)
                {
                    // try another name
                    continue;
                }
                else
                {
                    // errno is set by sem_open
                    return SEM_FAILED;
                }
            }
            else
            {
                // Now that it's open, we don't want any other processes to
                // access it by name.
                if (sem_unlink(name) != 0)
                {
                    LOG(LOG_WARNING,
                        "failed to unlink semaphore %s, continuing anyway",
                        name);
                }

                return ret;
            }
        }

        LOG(LOG_ERR, "failed to create a semaphore after %d tries",
            SEM_OPEN_MAX_TRIES);
        errno = EAGAIN;
        return SEM_FAILED;
    }
}

int semcompat_free(
    sem_t * sem)
{
    int ret = 0;
    int ret_errno = 0;

    if (pthread_once(&support_unnamed_initialized, initialize_support_unnamed) != 0)
    {
        // errno is set by pthread_once
        return -1;
    }

    if (support_unnamed)
    {
        if (sem_destroy(sem) != 0)
        {
            ret = -1;
            ret_errno = errno;
        }

        free(sem);

        errno = ret_errno;
        return ret;
    }
    else
    {
        return sem_close(sem);
    }
}
