#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <inttypes.h>

#include "logutils.h"
#include "macros.h"

#include "config.h"
#include "common.h"
#include "pdu.h"

#include "connection.h"
#include "db.h"

#define LOG_PREFIX "[connection] "


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

	uint8_t pdu_recv_buffer[MAX_PDU_SIZE];
	size_t pdu_recv_buffer_length;

	uint8_t pdu_send_buffer[MAX_PDU_SIZE];
	size_t pdu_send_buffer_length;

	PDU pdu; // this can have pointers into pdu_buffer
	PDU * pdup; // this can't

	struct db_response * response;

	// There can only be one outstanding request at a time, so this is it. No malloc() or free().
	struct db_request request;
};


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

	run_state->fd = argsp->socket;
	run_state->semaphore = argsp->semaphore;
	run_state->db_request_queue = argsp->db_request_queue;
	run_state->db_semaphores_all = argsp->db_semaphores_all;
	run_state->global_cache_state = argsp->global_cache_state;

	free(args_voidp);
	args_voidp = NULL;

	run_state->state = READY;

	run_state->db_response_queue = NULL;
	run_state->to_process_queue = NULL;

	run_state->pdu_recv_buffer_length = 0;
	run_state->pdu_send_buffer_length = 0;

	run_state->pdup = NULL;

	run_state->response = NULL;

	COMPILE_TIME_ASSERT(PDU_HEADER_LENGTH <= MAX_PDU_SIZE);
}


/** Send a PDU */
static void send_pdu(struct run_state * run_state, const PDU * pdu)
{
	ssize_t retval;
	ssize_t count;

	if (pdu == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "send_pdu got NULL pdu");
		pthread_exit(NULL);
	}

	count = dump_pdu(run_state->pdu_send_buffer, MAX_PDU_SIZE, pdu);
	if (count < 0)
	{
		log_msg(LOG_ERR, LOG_PREFIX "dump_pdu failed");
		pthread_exit(NULL);
	}
	else
	{
		run_state->pdu_send_buffer_length = count;
	}

	while (count > 0)
	{
		retval = write(run_state->fd,
			run_state->pdu_send_buffer + run_state->pdu_send_buffer_length - count,
			(size_t)count);
		if (retval < 0)
		{
			log_error(errno, run_state->errorbuf, LOG_PREFIX "write()");
			pthread_exit(NULL);
		}

		count -= retval;
	}
}


/** Repeatedly read into run_state->pdu_buffer until count is fulfilled. */
static void read_block(struct run_state * run_state, ssize_t count)
{
	ssize_t retval;

	while (count > 0)
	{
		switch (parse_pdu(run_state->pdu_recv_buffer, run_state->pdu_recv_buffer_length, &run_state->pdu))
		{
			case PDU_GOOD:
			case PDU_WARNING:
				log_msg(LOG_WARNING, LOG_PREFIX "tried to read past the end of a PDU");
				// TODO: send error
				pthread_exit(NULL);
			case PDU_ERROR:
				log_msg(LOG_NOTICE, LOG_PREFIX "received invalid PDU");
				// TODO: send error
				pthread_exit(NULL);
			case PDU_TRUNCATED:
				// this is good because we're expecting to read more
				break;
			default:
				log_msg(LOG_ERR, LOG_PREFIX "unexpected return value from parse_pdu()");
				// TODO: send error
				pthread_exit(NULL);
		}

		retval = read(run_state->fd, run_state->pdu_recv_buffer + run_state->pdu_recv_buffer_length, (size_t)count);
		if (retval < 0)
		{
			log_error(errno, run_state->errorbuf, "read()");
		}
		else if (retval == 0)
		{
			log_msg(LOG_NOTICE, LOG_PREFIX "remote side closed connection in the middle of sending a PDU");
			pthread_exit(NULL);
		}
		else
		{
			count -= retval;
			run_state->pdu_recv_buffer_length += retval;
		}
	}
}

/** Try to read into run_state->pdu_buffer up to count bytes, return true if any data was read, false if no data was read. */
static bool read_nonblock(struct run_state * run_state, size_t count)
{
	if (count <= 0)
		return true;

	ssize_t retval;

	retval = recv(run_state->fd,
		run_state->pdu_recv_buffer + run_state->pdu_recv_buffer_length,
		count,
		MSG_DONTWAIT);

	if (retval < 0)
	{
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			log_error(errno, run_state->errorbuf, LOG_PREFIX "recv()");

		return false;
	}
	else if (retval == 0)
	{
		log_msg(LOG_INFO, LOG_PREFIX "remote side closed connection");
		pthread_exit(NULL);
	}
	else
	{
		run_state->pdu_recv_buffer_length += retval;

		return true;
	}
}

/** Read (blocking) up to a PDU boundary. See parse_pdu() for return value. */
static int read_and_parse_pdu(struct run_state * run_state)
{
	int retval;

	retval = parse_pdu(run_state->pdu_recv_buffer, run_state->pdu_recv_buffer_length, &run_state->pdu);

	if (retval == PDU_ERROR)
	{
		return retval;
	}

	read_block(run_state, PDU_HEADER_LENGTH - run_state->pdu_recv_buffer_length);

	retval = parse_pdu(run_state->pdu_recv_buffer, run_state->pdu_recv_buffer_length, &run_state->pdu);

	if (retval == PDU_TRUNCATED)
	{
		if (run_state->pdu.length > MAX_PDU_SIZE)
		{
			log_msg(LOG_NOTICE,
				LOG_PREFIX "received PDU that's too long (%" PRIu32 " bytes)",
				run_state->pdu.length);
			// TODO: send error
			pthread_exit(NULL);
		}

		read_block(run_state,
			run_state->pdu.length - run_state->pdu_recv_buffer_length);

		retval = parse_pdu(run_state->pdu_recv_buffer, run_state->pdu_recv_buffer_length, &run_state->pdu);
	}

	return retval;
}

static void add_db_request(struct run_state * run_state, PDU * pdu)
{
	if (Queue_size(run_state->db_response_queue) != 0)
	{
		log_msg(LOG_ERR, LOG_PREFIX "add_db_request called with non-empty response queue");
		// TODO: send error
		pthread_exit(NULL);
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
			// TODO: send error
			pthread_exit(NULL);
	}

	run_state->request.response_queue = run_state->db_response_queue;
	run_state->request.response_semaphore = run_state->semaphore;
	run_state->request.cancel_request = false;

	if (!Queue_push(run_state->db_request_queue, (void *)&run_state->request))
	{
		log_msg(LOG_ERR, LOG_PREFIX "couldn't add new request to request queue");
		// TODO: send error
		pthread_exit(NULL);
	}

	run_state->state = RESPONDING;

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
}

static void push_to_process_queue(struct run_state * run_state, const PDU * pdu)
{
	PDU * pdup = pdu_deepcopy(pdu);
	if (pdup == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't allocate memory for a copy of the PDU");
		// TODO: send error
		pthread_exit(NULL);
	}

	// TODO: make the thread temporarily not cancelable so pdup always gets free()d?

	if (!Queue_push(run_state->to_process_queue, (void *)pdup))
	{
		pdu_free(pdup);
		log_msg(LOG_ERR, LOG_PREFIX "can't push a PDU onto the to-process queue");
		// TODO: send error
		pthread_exit(NULL);
	}
}

static void read_and_handle_pdu(struct run_state * run_state)
{
	int retval = read_and_parse_pdu(run_state);

	switch (retval)
	{
		case PDU_ERROR:
			log_msg(LOG_NOTICE, LOG_PREFIX "received invalid PDU");
			// TODO: send error
			pthread_exit(NULL);
		case PDU_WARNING:
			log_msg(LOG_NOTICE, LOG_PREFIX "received a PDU with unsupported feature(s)");
		case PDU_GOOD:
			// TODO: handle this correctly instead of this stub
			if (run_state->state == RESPONDING)
			{
				push_to_process_queue(run_state, &run_state->pdu);
			}
			else
			{
				add_db_request(run_state, &run_state->pdu);
			}
			break;
		default:
			log_msg(LOG_ERR,
				LOG_PREFIX "read_and_parse_pdu() returned an unexpected value (%d)",
				retval);
			// TODO: send error
			pthread_exit(NULL);
	}
}

static void handle_response(struct run_state * run_state)
{
	size_t i;

	if (run_state->response == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "got NULL response from db");
		return;
	}

	if (run_state->response->more_data_semaphore != NULL)
	{
		if (sem_post(run_state->response->more_data_semaphore) != 0)
		{
			log_error(errno, run_state->errorbuf, LOG_PREFIX "sem_post()");
		}
	}

	/* TODO:
		If any of response.PDUs indicate an update to cache_state:
			Update cache_state as appropriate.
	*/

	for (i = 0; i < run_state->response->num_PDUs; ++i)
	{
		send_pdu(run_state, &run_state->response->PDUs[i]);
	}

	if (run_state->response->more_data_semaphore == NULL)
	{
		run_state->state = READY;
		while (run_state->state == READY &&
			Queue_trypop(run_state->to_process_queue, (void **)&run_state->pdup))
		{
			// TODO: handle this for real instead of this stub
			add_db_request(run_state, run_state->pdup);

			pdu_free(run_state->pdup);
			run_state->pdup = NULL;
		}
	}

	pdu_free_array(run_state->response->PDUs, run_state->response->num_PDUs);
	free((void *)run_state->response);
	run_state->response = NULL;
}


// I think this function shouldn't call pthread_exit() because it's called from cleanup()
static bool wait_on_semaphore(struct run_state * run_state, bool use_timeout)
{
	static const struct timespec semaphore_timeout = {CXN_CACHE_STATE_INTERVAL, 0};

	int retval;

	if (use_timeout)
		retval = sem_timedwait(run_state->semaphore, &semaphore_timeout);
	else
		retval = sem_wait(run_state->semaphore);

	if (retval == -1 && errno == ETIMEDOUT)
	{
		return true;
	}
	else if (retval != 0)
	{
		log_error(errno, run_state->errorbuf, LOG_PREFIX "waiting for semaphore");
		return false;
	}
	else
	{
		return true;
	}
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

		// TODO: increment all the DB semaphores (or the correct one if we can determine which it is)

		while (true)
		{
			if (!wait_on_semaphore(run_state, false))
			{
				log_msg(LOG_ERR, LOG_PREFIX "failed to wait on semaphore in cleanup(), continuing without clearing the db response queue");
				break;
			}

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

	while (Queue_trypop(run_state->to_process_queue, (void **)&run_state->pdup))
	{
		pdu_free(run_state->pdup);
	}
	run_state->pdup = NULL;
	Queue_free(run_state->to_process_queue);
	run_state->to_process_queue = NULL;
}


static void initialize_data_structures_in_run_state(struct run_state * run_state)
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

static void connection_main_loop(struct run_state * run_state)
{
	if (!wait_on_semaphore(run_state, true))
		pthread_exit(NULL);

	run_state->pdu_recv_buffer_length = 0;

	if (read_nonblock(run_state, PDU_HEADER_LENGTH))
	{
		read_and_handle_pdu(run_state);
	}
	else if (run_state->state == RESPONDING &&
		Queue_trypop(run_state->db_response_queue, (void **)&run_state->response))
	{
		handle_response(run_state);
	}

	// TODO: check global_cache_state
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
		connection_main_loop(&run_state);
	}

	pthread_cleanup_pop(1);
}
