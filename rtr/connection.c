#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>

#include "macros.h"

#include "config.h"
#include "logging.h"
#include "pdu.h"

#include "connection.h"
#include "db.h"


#define ERROR_TEXT(str) (uint8_t *)str, strlen(str)


struct run_state {
	int fd;
	cxn_semaphore_t * semaphore;
	Queue * db_request_queue;
	db_semaphore_t * db_semaphore;
	struct global_cache_state * global_cache_state;
	struct cache_state local_cache_state;

	enum {READY, RESPONDING} state;

	char errorbuf[ERROR_BUF_SIZE];
	char pdustrbuf[PDU_SPRINT_BUFSZ];

	Queue * db_response_queue;
	Queue * to_process_queue;

	uint8_t pdu_recv_buffer[MAX_PDU_SIZE];
	size_t pdu_recv_buffer_length;

	uint8_t pdu_send_buffer[MAX_PDU_SIZE];
	size_t pdu_send_buffer_length;

	PDU recv_pdu; // this can have pointers into pdu_recv_buffer
	PDU send_pdu; // ditto
	PDU * pdup; // this can't

	struct db_response * response;

	// There can only be one outstanding request at a time, so this is it. No malloc() or free().
	struct db_request request;

	// tv_nsec MUST be zero
	struct timespec next_cache_state_check_time;
};


static void copy_cache_state(struct run_state * run_state, struct cache_state * cache_state)
{
	int retval;

	retval = pthread_rwlock_rdlock(&run_state->global_cache_state->lock);

	if (retval != 0)
	{
		ERR_LOG(retval, run_state->errorbuf, "pthread_rwlock_rdlock()");
		pthread_exit(NULL);
	}

	*cache_state = run_state->global_cache_state->cache_state;

	retval = pthread_rwlock_unlock(&run_state->global_cache_state->lock);

	if (retval != 0)
	{
		ERR_LOG(retval, run_state->errorbuf, "pthread_rwlock_unlock()");
		pthread_exit(NULL);
	}

	run_state->next_cache_state_check_time.tv_sec = time(NULL) + CXN_CACHE_STATE_INTERVAL;
}


static void initialize_run_state(struct run_state * run_state, void * args_voidp)
{
	struct connection_main_args * argsp = (struct connection_main_args *)args_voidp;

	if (argsp == NULL ||
		argsp->semaphore == NULL ||
		argsp->db_request_queue == NULL ||
		argsp->db_semaphore == NULL ||
		argsp->global_cache_state == NULL)
	{
		LOG(LOG_ERR, "got NULL argument");
		free(args_voidp);
		pthread_exit(NULL);
	}

	run_state->fd = argsp->socket;
	run_state->semaphore = argsp->semaphore;
	run_state->db_request_queue = argsp->db_request_queue;
	run_state->db_semaphore = argsp->db_semaphore;
	run_state->global_cache_state = argsp->global_cache_state;

	free(args_voidp);
	args_voidp = NULL;

	copy_cache_state(run_state, &run_state->local_cache_state);

	run_state->state = READY;

	run_state->db_response_queue = NULL;
	run_state->to_process_queue = NULL;

	run_state->pdu_recv_buffer_length = 0;
	run_state->pdu_send_buffer_length = 0;

	run_state->pdup = NULL;

	run_state->response = NULL;

	run_state->next_cache_state_check_time.tv_sec = time(NULL) + CXN_NOTIFY_INTERVAL;
	run_state->next_cache_state_check_time.tv_nsec = 0;

	COMPILE_TIME_ASSERT(PDU_HEADER_LENGTH <= MAX_PDU_SIZE);
}


/** Send a PDU */
static void send_pdu(struct run_state * run_state, const PDU * pdu)
{
	ssize_t retval;
	ssize_t count;

	if (pdu == NULL)
	{
		LOG(LOG_ERR, "send_pdu got NULL pdu");
		pthread_exit(NULL);
	}

	count = dump_pdu(run_state->pdu_send_buffer, MAX_PDU_SIZE, pdu);
	if (count < 0)
	{
		LOG(LOG_ERR, "dump_pdu failed");
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
			ERR_LOG(errno, run_state->errorbuf, "write()");
			pthread_exit(NULL);
		}

		count -= retval;
	}
}

static void send_cache_reset(struct run_state * run_state)
{
	run_state->send_pdu.protocolVersion = RTR_PROTOCOL_VERSION;
	run_state->send_pdu.pduType = PDU_CACHE_RESET;
	run_state->send_pdu.reserved = 0;
	run_state->send_pdu.length = PDU_HEADER_LENGTH;

	send_pdu(run_state, &run_state->send_pdu);
}

static void send_error(struct run_state * run_state, error_code_t code,
	uint8_t * embedded_pdu, size_t embedded_pdu_length,
	uint8_t * error_text, size_t error_text_length)
{
	if (PDU_HEADER_LENGTH + PDU_ERROR_HEADERS_LENGTH + error_text_length > MAX_PDU_SIZE)
	{
		LOG(LOG_ERR, "send_error() called with too long of an error text");
		pthread_exit(NULL);
	}

	if (PDU_HEADER_LENGTH + PDU_ERROR_HEADERS_LENGTH + embedded_pdu_length + error_text_length > MAX_PDU_SIZE)
	{
		embedded_pdu_length = MAX_PDU_SIZE - (PDU_HEADER_LENGTH + PDU_ERROR_HEADERS_LENGTH + error_text_length);
	}

	run_state->send_pdu.protocolVersion = RTR_PROTOCOL_VERSION;
	run_state->send_pdu.pduType = PDU_ERROR_REPORT;
	run_state->send_pdu.errorCode = code;
	run_state->send_pdu.length = PDU_HEADER_LENGTH + PDU_ERROR_HEADERS_LENGTH + embedded_pdu_length + error_text_length;
	run_state->send_pdu.errorData.encapsulatedPDULength = embedded_pdu_length;
	run_state->send_pdu.errorData.encapsulatedPDU = embedded_pdu;
	run_state->send_pdu.errorData.errorTextLength = error_text_length;
	run_state->send_pdu.errorData.errorText = error_text;

	send_pdu(run_state, &run_state->send_pdu);
}

// If embed_from_recv_buffer: get the PDU from the receive buffer and ignore embedded_pdu.
// It !embed_from_recv_buffer: dump embedded_pdu into the receive buffer.
static void send_error_from_parsed_pdu(struct run_state * run_state, error_code_t code,
	const PDU * embedded_pdu, bool embed_from_recv_buffer,
	uint8_t * error_text, size_t error_text_length)
{
	if (embed_from_recv_buffer)
	{
		send_error(run_state, code,
			run_state->pdu_recv_buffer, run_state->pdu_recv_buffer_length,
			error_text, error_text_length);
		return;
	}

	if (PDU_HEADER_LENGTH + PDU_ERROR_HEADERS_LENGTH + error_text_length > MAX_PDU_SIZE)
	{
		LOG(LOG_ERR, "send_error_from_parsed_pdu() called with too long of an error text");
		pthread_exit(NULL);
	}

	size_t max_embedded_length = MAX_PDU_SIZE - (PDU_HEADER_LENGTH + PDU_ERROR_HEADERS_LENGTH + error_text_length);

	ssize_t retval = dump_pdu(run_state->pdu_recv_buffer, max_embedded_length, embedded_pdu);
	run_state->pdu_recv_buffer_length = 0;

	if (retval <= 0)
	{
		send_error(run_state, code,
			NULL, 0,
			error_text, error_text_length);
		return;
	}

	send_error(run_state, code,
		run_state->pdu_recv_buffer, (size_t)retval,
		error_text, error_text_length);
}

static void log_and_send_parse_error(struct run_state * run_state, int parse_pdu_retval)
{
	error_code_t code;

	switch (parse_pdu_retval)
	{
		case PDU_CORRUPT_DATA:
			LOG(LOG_NOTICE, "received PDU with corrupt data");
			code = ERR_CORRUPT_DATA;
			break;
		case PDU_INTERNAL_ERROR:
			LOG(LOG_NOTICE, "internal error from parsing a PDU");
			code = ERR_INTERNAL_ERROR;
			break;
		case PDU_UNSUPPORTED_PROTOCOL_VERSION:
			LOG(LOG_NOTICE, "received PDU with unsupported protocol version");
			code = ERR_UNSUPPORTED_VERSION;
			break;
		case PDU_UNSUPPORTED_PDU_TYPE:
			LOG(LOG_NOTICE, "received PDU with unsupported PDU type");
			code = ERR_UNSUPPORTED_TYPE;
			break;
		case PDU_INVALID_VALUE:
			LOG(LOG_NOTICE, "received PDU with an invalid value for a field");
			code = ERR_INVALID_REQUEST;
			break;
		default:
			LOG(LOG_ERR, "log_and_send_parse_error() called with unexpected parse_pdu_retval (%d)", parse_pdu_retval);
			code = ERR_INTERNAL_ERROR;
			break;
	}

	send_error(run_state, code,
		run_state->pdu_recv_buffer, run_state->pdu_recv_buffer_length,
		NULL, 0);
}

static void send_notify(struct run_state * run_state)
{
	if (!run_state->local_cache_state.data_available)
	{
		LOG(LOG_ERR, "can't send a Serial Notify when no data is available in the cache");
		pthread_exit(NULL);
	}

	run_state->send_pdu.protocolVersion = RTR_PROTOCOL_VERSION;
	run_state->send_pdu.pduType = PDU_SERIAL_NOTIFY;
	run_state->send_pdu.cacheNonce = run_state->local_cache_state.nonce;
	run_state->send_pdu.length = PDU_HEADER_LENGTH + sizeof(serial_number_t);
	run_state->send_pdu.serialNumber = run_state->local_cache_state.serial_number;

	send_pdu(run_state, &run_state->send_pdu);

	run_state->next_cache_state_check_time.tv_sec = time(NULL) + CXN_NOTIFY_INTERVAL;
}


/** Repeatedly read into run_state->pdu_recv_buffer until count is fulfilled. */
static void read_block(struct run_state * run_state, ssize_t count)
{
	ssize_t retval;
	int parse_retval;

	while (count > 0)
	{
		parse_retval = parse_pdu(run_state->pdu_recv_buffer, run_state->pdu_recv_buffer_length, &run_state->recv_pdu);
		switch (parse_retval)
		{
			case PDU_GOOD:
			case PDU_WARNING:
				LOG(LOG_WARNING, "tried to read past the end of a PDU");
				send_error(run_state, ERR_INTERNAL_ERROR, NULL, 0, NULL, 0);
				pthread_exit(NULL);
			case PDU_TRUNCATED:
				// this is good because we're expecting to read more
				break;
			default:
				log_and_send_parse_error(run_state, parse_retval);
				pthread_exit(NULL);
		}

		retval = read(run_state->fd, run_state->pdu_recv_buffer + run_state->pdu_recv_buffer_length, (size_t)count);
		if (retval < 0)
		{
			ERR_LOG(errno, run_state->errorbuf, "read()");
		}
		else if (retval == 0)
		{
			LOG(LOG_NOTICE, "remote side closed connection in the middle of sending a PDU");
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
			ERR_LOG(errno, run_state->errorbuf, "recv()");

		return false;
	}
	else if (retval == 0)
	{
		LOG(LOG_INFO, "remote side closed connection");
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

	retval = parse_pdu(run_state->pdu_recv_buffer, run_state->pdu_recv_buffer_length, &run_state->recv_pdu);

	if (PDU_IS_ERROR(retval))
	{
		return retval;
	}

	read_block(run_state, PDU_HEADER_LENGTH - run_state->pdu_recv_buffer_length);

	retval = parse_pdu(run_state->pdu_recv_buffer, run_state->pdu_recv_buffer_length, &run_state->recv_pdu);

	if (retval == PDU_TRUNCATED)
	{
		if (run_state->recv_pdu.length > MAX_PDU_SIZE)
		{
			LOG(LOG_NOTICE,
				"received PDU that's too long (%" PRIu32 " bytes)",
				run_state->recv_pdu.length);
			send_error(run_state, ERR_CORRUPT_DATA,
				run_state->pdu_recv_buffer, run_state->pdu_recv_buffer_length,
				ERROR_TEXT("PDU too large"));
			pthread_exit(NULL);
		}

		read_block(run_state,
			run_state->recv_pdu.length - run_state->pdu_recv_buffer_length);

		retval = parse_pdu(run_state->pdu_recv_buffer, run_state->pdu_recv_buffer_length, &run_state->recv_pdu);
	}

	return retval;
}

static void increment_db_semaphore(struct run_state * run_state)
{
	if (sem_post(run_state->db_semaphore) != 0)
	{
		ERR_LOG(errno, run_state->errorbuf, "sem_post()");
	}
}

static void add_db_request(struct run_state * run_state, PDU * pdu, bool pdu_from_recv_buffer)
{
	if (Queue_size(run_state->db_response_queue) != 0)
	{
		LOG(LOG_ERR, "add_db_request called with non-empty response queue");
		send_error_from_parsed_pdu(run_state, ERR_INTERNAL_ERROR,
			pdu, pdu_from_recv_buffer,
			NULL, 0);
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
			LOG(LOG_ERR, "add_db_request() called with a non-query PDU");
			send_error_from_parsed_pdu(run_state, ERR_INTERNAL_ERROR,
				pdu, pdu_from_recv_buffer,
				NULL, 0);
			pthread_exit(NULL);
	}

	run_state->request.response_queue = run_state->db_response_queue;
	run_state->request.response_semaphore = run_state->semaphore;
	run_state->request.cancel_request = false;

	if (!Queue_push(run_state->db_request_queue, (void *)&run_state->request))
	{
		LOG(LOG_ERR, "couldn't add new request to request queue");
		send_error_from_parsed_pdu(run_state, ERR_INTERNAL_ERROR,
			pdu, pdu_from_recv_buffer,
			NULL, 0);
		pthread_exit(NULL);
	}

	run_state->state = RESPONDING;

	increment_db_semaphore(run_state);
}

static void push_to_process_queue(struct run_state * run_state, const PDU * pdu, bool pdu_from_recv_buffer)
{
	PDU * pdup = pdu_deepcopy(pdu);
	if (pdup == NULL)
	{
		LOG(LOG_ERR, "can't allocate memory for a copy of the PDU");
		send_error_from_parsed_pdu(run_state, ERR_INTERNAL_ERROR,
			pdu, pdu_from_recv_buffer,
			NULL, 0);
		pthread_exit(NULL);
	}

	// TODO: make the thread temporarily not cancelable so pdup always gets free()d?

	if (!Queue_push(run_state->to_process_queue, (void *)pdup))
	{
		pdu_free(pdup);
		LOG(LOG_ERR, "can't push a PDU onto the to-process queue");
		send_error_from_parsed_pdu(run_state, ERR_INTERNAL_ERROR,
			pdu, pdu_from_recv_buffer,
			NULL, 0);
		pthread_exit(NULL);
	}
}

static void handle_pdu(struct run_state * run_state, PDU * pdup, bool pdu_from_recv_buffer)
{
	switch (pdup->pduType)
	{
		case PDU_SERIAL_QUERY:
			if (pdup->cacheNonce != run_state->local_cache_state.nonce)
			{
				LOG(LOG_INFO, "received wrong nonce (%" PRIu16 "), expected %" PRIu16,
					pdup->cacheNonce,
					run_state->local_cache_state.nonce);
				send_cache_reset(run_state);
				break;
			}
		case PDU_RESET_QUERY:
			if (run_state->state == RESPONDING)
			{
				push_to_process_queue(run_state, pdup, pdu_from_recv_buffer);
			}
			else
			{
				add_db_request(run_state, pdup, pdu_from_recv_buffer);
			}
			break;
		case PDU_ERROR_REPORT:
			pdu_sprint(pdup, run_state->pdustrbuf);
			LOG(LOG_NOTICE, "received %s", run_state->pdustrbuf);
			pthread_exit(NULL);
		default:
			pdu_sprint(pdup, run_state->pdustrbuf);
			LOG(LOG_NOTICE, "received unexpected PDU: %s", run_state->pdustrbuf);
			send_error_from_parsed_pdu(run_state, ERR_INVALID_REQUEST,
				pdup, pdu_from_recv_buffer,
				ERROR_TEXT("unexpected PDU type"));
			pthread_exit(NULL);
	}
}

static void read_and_handle_pdu(struct run_state * run_state)
{
	int retval = read_and_parse_pdu(run_state);

	switch (retval)
	{
		case PDU_WARNING:
			LOG(LOG_NOTICE, "received a PDU with unsupported feature(s)");
		case PDU_GOOD:
			handle_pdu(run_state, &run_state->recv_pdu, true);
			break;
		default:
			log_and_send_parse_error(run_state, retval);
			pthread_exit(NULL);
	}
}

static void handle_response(struct run_state * run_state)
{
	size_t i;

	if (run_state->response == NULL)
	{
		LOG(LOG_ERR, "got NULL response from db");
		return;
	}

	if (!run_state->response->is_done)
	{
		increment_db_semaphore(run_state);
	}

	/* TODO:
		If any of response.PDUs indicate an update to cache_state:
			Update cache_state as appropriate.
	*/

	for (i = 0; i < run_state->response->num_PDUs; ++i)
	{
		send_pdu(run_state, &run_state->response->PDUs[i]);
	}

	bool is_done = run_state->response->is_done;

	pdu_free_array(run_state->response->PDUs, run_state->response->num_PDUs);
	free((void *)run_state->response);
	run_state->response = NULL;

	if (is_done)
	{
		run_state->state = READY;
		while (run_state->state == READY &&
			Queue_trypop(run_state->to_process_queue, (void **)&run_state->pdup))
		{
			handle_pdu(run_state, run_state->pdup, false);

			pdu_free(run_state->pdup);
			run_state->pdup = NULL;
		}
	}
}


static void check_global_cache_state(struct run_state * run_state)
{
	struct cache_state tmp_cache_state;

	if (run_state->state != READY)
	{
		LOG(LOG_ERR, "check_global_cache_state() called when not in READY state");
		pthread_exit(NULL);
	}

	copy_cache_state(run_state, &tmp_cache_state);

	if (run_state->local_cache_state.nonce != tmp_cache_state.nonce)
	{
		LOG(LOG_ERR, "cache nonce has changed");
		pthread_exit(NULL);
	}

	if (tmp_cache_state.data_available && (
		!run_state->local_cache_state.data_available ||
		run_state->local_cache_state.serial_number != tmp_cache_state.serial_number))
	{
		run_state->local_cache_state.serial_number = tmp_cache_state.serial_number;
		run_state->local_cache_state.data_available = tmp_cache_state.data_available;
		send_notify(run_state);
	}
}


// I think this function shouldn't call pthread_exit() because it's called from cleanup()
static bool wait_on_semaphore(struct run_state * run_state, bool use_timeout)
{
	int retval;

	if (use_timeout && run_state->state == READY) // if we're RESPONDING, we can't send a Notify anyway
	{
		run_state->next_cache_state_check_time.tv_sec += 1;
		retval = sem_timedwait(run_state->semaphore, &run_state->next_cache_state_check_time);
	}
	else
	{
		retval = sem_wait(run_state->semaphore);
	}

	if (retval == -1 && errno == ETIMEDOUT)
	{
		return true;
	}
	else if (retval != 0)
	{
		ERR_LOG(errno, run_state->errorbuf,
			((use_timeout && run_state->state == READY) ?
				"sem_timedwait()" :
				"sem_wait()"));
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
		if (run_state->response->is_done)
			run_state->state = READY;

		pdu_free_array(run_state->response->PDUs, run_state->response->num_PDUs);
		free((void *)run_state->response);
		run_state->response = NULL;
	}

	if (run_state->state == RESPONDING)
	{
		run_state->request.cancel_request = true;

		increment_db_semaphore(run_state);

		while (true)
		{
			if (!wait_on_semaphore(run_state, false))
			{
				LOG(LOG_ERR, "failed to wait on semaphore in cleanup(), continuing without clearing the db response queue");
				break;
			}

			if (!Queue_trypop(run_state->db_response_queue, (void **)&run_state->response))
				continue;

			if (run_state->response == NULL)
				continue;

			pdu_free_array(run_state->response->PDUs, run_state->response->num_PDUs);

			if (run_state->response->is_done)
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
		LOG(LOG_ERR, "can't create db response queue");
		pthread_exit(NULL);
	}

	run_state->to_process_queue = Queue_new(false);
	if (run_state->to_process_queue == NULL)
	{
		LOG(LOG_ERR, "can't create to-process queue");
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

	if (run_state->state == READY &&
		time(NULL) >= run_state->next_cache_state_check_time.tv_sec)
	{
		check_global_cache_state(run_state);
	}
}


void * connection_main(void * args_voidp)
{
	struct run_state run_state;
	initialize_run_state(&run_state, args_voidp);

	pthread_cleanup_push(cleanup, &run_state);

	initialize_data_structures_in_run_state(&run_state);

	while (true)
	{
		connection_main_loop(&run_state);
	}

	pthread_cleanup_pop(1);
}
