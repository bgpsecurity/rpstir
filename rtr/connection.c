#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>

#include "logutils.h"
#include "macros.h"

#include "config.h"
#include "common.h"
#include "pdu.h"

#include "connection.h"
#include "db.h"

#define LOG_PREFIX "[connection] "

/*
TODO:

Make sure that all resources are cleaned up by functions passed to pthread_cleanup_push, except for the resources that are given by the connection control thread.

Make sure that cleanup ensures no other threads (e.g. db threads) have access to the connection semaphore.

Make sure that cleanup cancels any DB requests.
*/

struct run_state {
	int fd;
	cxn_semaphore_t * semaphore;
	Queue * db_request_queue;
	Bag * db_semaphores_all;
	struct global_cache_state * global_cache_state;

	enum {READY, RESPONDING} state;

	char errorbuf[ERROR_BUF_SIZE];

	Queue * db_response_queue;
	Queue * to_process_queue;

	uint8_t pdu_buffer[MAX_PDU_SIZE];
	size_t pdu_buffer_length;

	PDU pdu; // this can have pointers into pdu_buffer
	PDU * pdup; // this can't

	struct db_response * response;

	// There can only be one outstanding request at a time, so this is it. No malloc() or free().
	struct db_request request;
};

static const struct timespec semaphore_timeout = {CXN_CACHE_STATE_INTERVAL, 0};


static void initialize_run_state(struct run_state * run_state, void * args_voidp)
{
	struct connection_main_args * argsp = (struct connection_main_args *)args_voidp;

	if (argsp == NULL ||
		argsp->semaphore == NULL ||
		argsp->db_request_queue == NULL ||
		argsp->db_semaphores_all == NULL ||
		argsp->global_cache_state == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "got NULL argument");
		free(args_voidp);
		pthread_exit(NULL);
	}

	run_state->fd = argsp->fd;
	run_state->semaphore = argsp->semaphore;
	run_state->db_request_queue = argsp->db_request_queue;
	run_state->db_semaphores_all = argsp->db_semaphores_all;
	run_state->global_cache_state = argsp->global_cache_state;

	free(args_voidp);
	args_voidp = NULL;

	run_state->state = READY;

	run_state->db_response_queue = NULL;
	run_state->to_process_queue = NULL;

	run_state->pdu_buffer_length = 0;

	run_state->pdup = NULL;

	run_state->response = NULL;

	COMPILE_TIME_ASSERT(PDU_HEADER_LENGTH <= MAX_PDU_SIZE);
}


/** Repeatedly read into run_state->pdu_buffer until count is fulfilled, return false if there are errors. */
static bool read_block(struct run_state * run_state, size_t offset, ssize_t count)
{
	ssize_t retval;

	while (count > 0)
	{
		switch (parse_pdu(run_state->pdu_buffer, offset, &run_state->pdu))
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

		retval = read(run_state->fd, run_state->pdu_buffer + offset, (size_t)count);
		if (retval < 0)
		{
			log_error(errno, run_state->errorbuf, "read()");
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

/** Send a PDU, return false if there are errors. */
static bool send_pdu(struct run_state * run_state, const PDU * pdu)
{
	ssize_t retval;
	ssize_t offset = 0;
	ssize_t count;

	if (pdu == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "send_pdu got NULL pdu");
		return false;
	}

	count = dump_pdu(run_state->pdu_buffer, MAX_PDU_SIZE, pdu);
	if (count < 0)
	{
		log_msg(LOG_ERR, LOG_PREFIX "dump_pdu failed");
		return false;
	}

	while (count > 0)
	{
		retval = write(run_state->fd, run_state->pdu_buffer + offset, (size_t)count);
		if (retval < 0)
		{
			log_error(errno, run_state->errorbuf, LOG_PREFIX "write()");
			return false;
		}

		offset += retval;
		count -= retval;
	}

	return true;
}


static bool add_db_request(struct run_state * run_state, PDU * pdu)
{
	if (Queue_size(run_state->db_response_queue) != 0)
	{
		log_msg(LOG_ERR, LOG_PREFIX "add_db_request called with non-empty response queue");
		return false;
	}

	switch (pdu->pduType)
	{
		case PDU_SERIAL_QUERY:
			run_state->request.query.type = SERIAL_QUERY;
			run_state->request.query.serial_query.serial = pdu->serialNumber;
			break;
		case PDU_RESET_QUERY:
			run_state->request.query.type = RESET_QUERY;
			break;
		default:
			log_msg(LOG_ERR, LOG_PREFIX "add_db_request() called with a non-query PDU");
			return false;
	}

	run_state->request.response_queue = db_response_queue;
	run_state->request.response_semaphore = cxn_semaphore;
	run_state->request.cancel_request = false;

	if (!Queue_push(run_state->db_request_queue, (void *)&run_state->request))
	{
		log_msg(LOG_ERR, LOG_PREFIX "couldn't add new request to request queue");
		return false;
	}

	Bag_start_iteration(run_state->db_semaphores_all);
	Bag_iterator db_sem_it;
	db_semaphore_t * db_sem;
	for (db_sem_it = Bag_begin(run_state->db_semaphores_all);
		db_sem_it != Bag_end(run_state->db_semaphores_all);
		db_sem_it = Bag_iterator_next(run_state->db_semaphores_all, db_sem_it))
	{
		db_sem = Bag_get(run_state->db_semaphores_all, db_sem_it);
		if (db_sem == NULL)
		{
			log_msg(LOG_ERR, LOG_PREFIX "found NULL db semaphore");
		}
		else
		{
			if (sem_post(db_sem) != 0)
			{
				log_error(errno, run_state->errorbuf, LOG_PREFIX "sem_post()");
			}
		}
	}
	Bag_stop_iteration(run_state->db_semaphores_all);

	return true;
}


static void cleanup(void * run_state_voidp)
{
	struct run_state * run_state = (struct run_state *)run_state_voidp;

	if (run_state->response != NULL)
	{
		if (run_state->response->more_data_semaphore == NULL)
			run_state->state = READY;

		pdu_free_array(run_state->response->PDUs, run_state->response->num_PDUs);
		free((void *)run_state->response);
		run_state->response = NULL;
	}

	if (run_state->state == RESPONDING)
	{
		run_state->request.cancel_request = true;
		while (true)
		{
			// TODO: wait on the semaphore

			if (!Queue_trypop(run_state->db_response_queue, (void **)run_state->response))
				continue;

			if (run_state->response == NULL)
				continue;

			pdu_free_array(run_state->response->PDUs, run_state->response->num_PDUs);

			if (run_state->response->more_data_semaphore == NULL)
			{
				free((void *)run_state->response);
				break;
			}

			free((void *)run_state->response);
		}
		run_state->response = NULL;
	}

	Queue_free(run_state->db_response_queue);
	run_state->db_response_queue = NULL;

	if (run_state->pdup != NULL)
	{
		pdu_free(run_state->pdup);
		run_state->pdup = NULL;
	}

	while (Queue_trypop(to_process_queue, (void **)&run_state->pdup))
	{
		pdu_free(run_state->pdup);
	}
	run_state->pdup = NULL;
	Queue_free(to_process_queue);
	run_state->to_process_queue = NULL;
}


void initialize_data_structures_in_run_state(struct run_state * run_state)
{
	run_state->db_response_queue = Queue_new(true);
	if (run_state->db_response_queue == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't create db response queue");
		pthread_exit(NULL);
	}

	run_state->to_process_queue = Queue_new(false);
	if (run_state->to_process_queue == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't create to-process queue");
		pthread_exit(NULL);
	}
}


void * connection_main(void * args_voidp)
{
	struct run_state run_state;
	initialize_run_state(&run_state, args_voidp);

	pthread_cleanup_push(cleanup, &run_state);

	initialize_data_structures_in_run_state(&run_state);


	/* TODO:
	Lock global_cache_state.lock for reading.
	Let cache_state_t cache_state = copy of global_cache_state.cache_state.
	Unlock global_cache_state.lock.
	*/

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
			pthread_exit(NULL);
		}

		ssz_retval1 = recv(argsp->socket, pdu_buffer, PDU_HEADER_LENGTH, MSG_DONTWAIT);
		if (ssz_retval1 < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
		{
			log_error(errno, errorbuf, LOG_PREFIX "recv()");
		}
		else if (ssz_retval1 == 0)
		{
			log_msg(LOG_INFO, LOG_PREFIX "remote side closed connection");
			pthread_exit(NULL);
		}
		else if (ssz_retval1 > 0)
		{
			if (!read_block(argsp->socket, pdu_buffer, ssz_retval1, PDU_HEADER_LENGTH - ssz_retval1, &pdu, errorbuf))
			{
				pthread_exit(NULL);
			}

			retval1 = parse_pdu(pdu_buffer, PDU_HEADER_LENGTH, &pdu);
			if (retval1 == PDU_ERROR || pdu.length > MAX_PDU_SIZE)
			{
				// TODO: log and send error
				pthread_exit(NULL);
			}
			else if (retval1 == PDU_TRUNCATED)
			{
				length = pdu.length;
				if (!read_block(argsp->socket, pdu_buffer, PDU_HEADER_LENGTH, length - PDU_HEADER_LENGTH, &pdu, errorbuf))
				{
					pthread_exit(NULL);
				}

				retval1 = parse_pdu(pdu_buffer, length, &pdu);
			}

			switch (retval1)
			{
				case PDU_ERROR:
					// TODO: log and send error
					pthread_exit(NULL);
				case PDU_TRUNCATED:
					log_msg(LOG_ERR, LOG_PREFIX "parse_pdu() returned truncated when passed a non-truncated pdu");
					pthread_exit(NULL);
				case PDU_WARNING:
					log_msg(LOG_NOTICE, LOG_PREFIX "received a PDU with unsupported feature(s)");
				case PDU_GOOD:
					// TODO: handle this correctly instead of this stub
					if (state == RESPONDING)
					{
						pdup = pdu_deepcopy(&pdu);
						if (pdup == NULL || !Queue_push(to_process_queue, (void *)pdup))
						{
							if (pdup == NULL)
							{
								log_msg(LOG_ERR, LOG_PREFIX "can't allocate memory for a copy of the PDU");
							}
							else
							{
								pdu_free(pdup);
								log_msg(LOG_ERR, LOG_PREFIX "can't push a PDU onto the to-process queue");
							}
							// TODO: send error
							pthread_exit(NULL);
						}
					}
					else
					{
						if (!add_db_request(&request, &pdu, db_response_queue, argsp->semaphore, argsp->db_request_queue, argsp->db_semaphores_all, errorbuf))
						{
							log_msg(LOG_ERR, LOG_PREFIX "can't send a db request");
							// TODO: send error
							pthread_exit(NULL);
						}
						state = RESPONDING;
					}
					break;
				default:
					log_msg(LOG_ERR, LOG_PREFIX "parse_pdu() returned an unknown value");
					pthread_exit(NULL);
			}
		}
		else if (state == RESPONDING && Queue_trypop(db_response_queue, (void **)&response))
		{
			if (response == NULL)
			{
				log_msg(LOG_ERR, LOG_PREFIX "got NULL response from db");
			}
			else
			{
				if (response->more_data_semaphore != NULL)
				{
					if (sem_post(response->more_data_semaphore) != 0)
					{
						log_error(errno, errorbuf, LOG_PREFIX "sem_post()");
					}
				}

				/* TODO:
					If any of response.PDUs indicate an update to cache_state:
						Update cache_state as appropriate.
				*/

				for (i = 0; i < (ssize_t)response->num_PDUs; ++i)
				{
					if (!send_pdu(argsp->socket, pdu_buffer, &response->PDUs[i], errorbuf))
					{
						log_msg(LOG_ERR, LOG_PREFIX "failed sending a PDU response from the db");
						pdu_free_array(response->PDUs, response->num_PDUs);
						free((void *)response);
						pthread_exit(NULL);
					}
				}

				if (response->more_data_semaphore == NULL)
				{
					state = READY;
					while (state == READY && Queue_trypop(to_process_queue, (void **)&pdup))
					{
						// TODO: handle this for real instead of this stub
						if (!add_db_request(&request, pdup, db_response_queue, argsp->semaphore, argsp->db_request_queue, argsp->db_semaphores_all, errorbuf))
						{
							log_msg(LOG_ERR, LOG_PREFIX "can't send a db request");
							// TODO: send error
							pdu_free(pdup);
							pthread_exit(NULL);
						}

						pdu_free(pdup);

						state = RESPONDING;
					}
				}
			}
		}

		// TODO: check global_cache_state
	}

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
}
