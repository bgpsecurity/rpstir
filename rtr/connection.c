#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "logutils.h"
#include "macros.h"

#include "config.h"
#include "common.h"
#include "pdu.h"

#include "connection.h"

#define LOG_PREFIX "[connection] "

/*
TODO:

Make sure that all resources are cleaned up by functions passed to pthread_cleanup_push, except for the resources that are given by the connection control thread.

Make sure that cleanup ensures no other threads (e.g. db threads) have access to the connection semaphore.

Make sure that cleanup cancels any DB requests.
*/

enum cxn_state {READY, RESPONDING};

/** Repeatedly read until count is fulfilled, return false if there are errors. */
static bool read_block(int fd, void * buffer, size_t offset, ssize_t count, PDU * pdu, char errorbuf[ERROR_BUF_SIZE])
{
	ssize_t retval;

	while (count > 0)
	{
		switch (parse_pdu(buffer, offset, pdu))
		{
			case PDU_GOOD:
			case PDU_WARNING:
				log_msg(LOG_WARNING, LOG_PREFIX "tried to read past the end of a PDU");
				return false;
			case PDU_ERROR:
				log_msg(LOG_NOTICE, LOG_PREFIX "received invalid PDU");
				return false;
			case PDU_TRUNCATED:
				// this is good because we're expecting to read more
				break;
			default:
				log_msg(LOG_ERR, LOG_PREFIX "unexpected return value from parse_pdu()");
				return false;
		}

		retval = read(fd, buffer, (size_t)count);
		if (retval < 0)
		{
			log_error(errno, errorbuf, "read()");
		}
		else if (retval == 0)
		{
			log_msg(LOG_NOTICE, LOG_PREFIX "remote side closed connection in the middle of sending a PDU");
			return false;
		}
		else
		{
			count -= retval;
			offset += retval;
		}
	}

	return true;
}

void * connection_main(void * args_voidp)
{
	int retval1;
	ssize_t ssz_retval1
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

	COMPILE_TIME_ASSERT(PDU_HEADER_LENGTH <= MAX_PDU_SIZE);
	COMPILE_TIME_ASSERT(PDU_HEADER_LENGTH > MAX_PDU_SIZE); // This should fail.. remove it once I know it fails
	uint8_t pdu_buffer[MAX_PDU_SIZE];
	PDU pdu;
	size_t length;

	enum cxn_state state = READY;

	/* TODO:
	Lock global_cache_state.lock for reading.
	Let cache_state_t cache_state = copy of global_cache_state.cache_state.
	Unlock global_cache_state.lock.
	*/

	const struct timespec semaphore_timeout = {CXN_CACHE_STATE_INTERVAL, 0};

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

		ssz_retval1 = recv(argsp->socket, pdu_buffer, PDU_HEADER_LENGTH, MSG_DONTWAIT);
		if (ssz_retval1 < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
		{
			log_error(errno, errorbuf, LOG_PREFIX "recv()");
		}
		else if (ssz_retval1 == 0)
		{
			log_msg(LOG_INFO, LOG_PREFIX "remote side closed connection");
			// TODO: cleanup
			return NULL;
		}
		else if (ssz_retval1 > 0)
		{
			if (!read_block(argsp->socket, pdu_buffer, ssz_retval1, PDU_HEADER_LENGTH - ssz_retval1, &pdu, errorbuf))
			{
				// TODO: cleanup
				return NULL;
			}

			retval1 = parse_pdu(pdu_buffer, PDU_HEADER_LENGTH, &pdu);
			if (retval1 == PDU_ERROR || pdu.length > MAX_PDU_SIZE)
			{
				// TODO: log and send error
				// TODO: cleanup
				return NULL;
			}
			else if (retval1 == PDU_TRUNCATED)
			{
				length = pdu.length;
				if (!read_block(argsp->socket, pdu_buffer, PDU_HEADER_LENGTH, length - PDU_HEADER_LENGTH, &pdu, errorbuf))
				{
					// TODO cleanup
					return NULL;
				}

				retval1 = parse_pdu(pdu_buffer, length, &pdu);
			}

			switch (retval1)
			{
				case PDU_ERROR:
					// TODO: log and send error
					// TODO: cleanup
					return NULL;
				case PDU_TRUNCATED:
					log_msg(LOG_ERR, LOG_PREFIX "parse_pdu() returned truncated when passed a non-truncated pdu");
					// TODO: cleanup
					return NULL;
				case PDU_WARNING:
					log_msg(LOG_NOTICE, LOG_PREFIX "received a PDU with unsupported feature(s)");
				case PDU_GOOD:
					// TODO
				default:
					log_msg(LOG_ERR, LOG_PREFIX "parse_pdu() returned an unknown value");
					// TODO: cleanup
					return NULL;
			}
		}
		else if (Queue_trypop ...)
	}
}
