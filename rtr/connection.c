#include <unistd.h>
#include <fcntl.h>

#include "logutils.h"

#include "config.h"
#include "common.h"

#include "connection.h"

#define LOG_PREFIX "[connection] "

/*
TODO:

Make sure that all resources are cleaned up by functions passed to pthread_cleanup_push, except for the resources that are given by the connection control thread.

Make sure that cleanup ensures no other threads (e.g. db threads) have access to the connection semaphore.

Make sure that cleanup cancels any DB requests.
*/

enum cxn_state {READY, RESPONDING};

void * connection_main(void * args_voidp)
{
	int retval1;
	char errorbuf[ERROR_BUF_SIZE];

	struct connection_main_args * argsp = (struct connection_main_args *)args_voidp;

	if (argsp == NULL ||
		argsp->semaphore == NULL ||
		argsp->db_request_queue == NULL ||
		argsp->db_semaphores_all == NULL ||
		argsp->global_cache_state == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "got NULL argument");
		free((void *)argsp);
		return NULL;
	}

	Queue * db_response_queue = Queue_new(true);
	if (db_response_queue == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't create db response queue");
		free((void *)argsp);
		return NULL;
	}

	Queue * to_process_queue = Queue_new(false);
	if (to_process_queue == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't create to-process queue");
		Queue_free(db_response_queue);
		free((void *)argsp);
		return NULL;
	}

	uint8_t pdu_buffer[MAX_PDU_SIZE];

	enum cxn_state state = READY;

	/* TODO:
	Lock global_cache_state.lock for reading.
	Let cache_state_t cache_state = copy of global_cache_state.cache_state.
	Unlock global_cache_state.lock.
	*/

	const struct timespec semaphore_timeout = {CXN_CACHE_STATE_INTERVAL, 0};

	if (fnctl(argsp->socket, F_SETFL, O_NONBLOCK | fnctl(argsp->socket, F_GETFL)) != 0)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't set socket to non-blocking mode");
		Queue_free(to_process_queue);
		Queue_free(db_response_queue);
		free((void *)argsp);
		return NULL;
	}

	while (true)
	{
		retval1 = sem_timedwait(argsp->semaphore, &semaphore_timeout);
		if (retval1 == -1 && errno == ETIMEDOUT)
		{
			continue; // TODO: stuff with cache_state
		}
		else if (retval1 != 0)
		{
			log_error(errno, errorbuf, LOG_PREFIX "sem_timedwait()");
			// TODO: cleanup
			return NULL;
		}

		// TODO
	}
}
