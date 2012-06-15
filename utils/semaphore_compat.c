#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <stdbool.h>
#include <pthread.h>

#include "semaphore_compat.h"

/*
   OpenBSD lacks sem_timedwait(), so we implement a simple version
   here.  This function is sufficient for the RTR server
   implementation because threads call this only when they are waiting
   with nothing to do.  In addition, for the RTR server, the max
   number of threads waiting on each semaphore is anticipated to be 1.

   Warning: this function may have limitations when compared to a
   standard implementation of sem_timedwait().

   According to Tanenbaum in _Modern Operating Systems_, critical
   regions should be designed to obey the following four conditions:

   1. (Mutal Exclusion) No two processes may be simultaneously inside
      their critical regions.
   2. No assumptions may be made about speeds or the number of CPUs.
   3. (Progress) No process running outside its critical region may
      block other processes.
   4. (Bounded wait) No process should have to wait forever to enter
      its critical region.

   Warning: this function does NOT ensure #4 (Bounded wait).  Also,
   this is minor, but in the unlikely event that nanosleep() fails
   repeatedly and we spin, there could be a soft violation of #3
   (Progress) due to priority inversion.
*/

#ifndef HAVE_SEM_TIMEDWAIT
int sem_timedwait(sem_t *sem, const struct timespec *abs_timeout)
{
	int retval;
	int sem_errno;
	struct timespec now;
	static const struct timespec sleep_interval = {0, 100000000L};

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

		if (clock_gettime(CLOCK_REALTIME, &now) != 0)
		{
			// unfortunately none of the valid errors for sem_timedwait actually match
			// this error, but EINVAL seems the closest
			sem_errno = EINVAL;
			break;
		}

		if (now.tv_sec > abs_timeout->tv_sec || (
			now.tv_sec == abs_timeout->tv_sec &&
			now.tv_nsec >= abs_timeout->tv_nsec))
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
