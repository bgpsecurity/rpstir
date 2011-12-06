#include <pthread.h>
#include <errno.h>

#include "macros.h"
#include "logging.h"
#include "mysql-c-api/connect.h"
#include "mysql-c-api/rtr.h"

#include "config.h"
#include "db.h"


struct db_request_state {
	struct db_request * request;
	void * query_state;
};

static void initialize_request_state(struct db_request_state * rq, struct db_request * request)
{
	rq->request = request;
	rq->query_state = NULL;
}

static int start_query(struct db_request_state * rq, void * db)
{
	switch (rq->request->query.type)
	{
		case SERIAL_QUERY:
			return startSerialQuery(db, &rq->query_state,
				rq->request->query.serial_query.serial);
		case RESET_QUERY:
			return startResetQuery(db, &rq->query_state);
		default:
			LOG(LOG_ERR, "got unexpected query type");
			return -1; // TODO: check if this is a good error code
	}
}

static ssize_t query_get_next(struct db_request_state * rq, void * db,
	size_t num_rows, PDU ** pdus, bool * is_done)
{
	switch (rq->request->query.type)
	{
		case SERIAL_QUERY:
			return serialQueryGetNext(db, rq->query_state,
				num_rows, pdus, is_done);
		case RESET_QUERY:
			return resetQueryGetNext(db, rq->query_state,
				num_rows, pdus, is_done);
		default:
			LOG(LOG_ERR, "got unexpected query type");
			*is_done = true;
			return -1; // TODO: check if this is a good error code
	}
}

static void stop_query(struct db_request_state * rq, void * db)
{
	if (rq->query_state != NULL)
	{
		switch (rq->request->query.type)
		{
			case SERIAL_QUERY:
				stopSerialQuery(db, rq->query_state);
				break;
			case RESET_QUERY:
				stopResetQuery(db, rq->query_state);
				break;
			default:
				LOG(LOG_ERR, "got unexpected query type");
				break;
		}
		rq->query_state = NULL;
	}
}


struct run_state {
	db_semaphore_t * semaphore;
	Queue * db_request_queue;
	Bag * db_currently_processing;
	void * db;

	char errorbuf[ERROR_BUF_SIZE];

	struct db_request * request;
	struct db_request_state * request_state;

	struct db_response * response;
};

static void initialize_run_state(struct run_state * run_state, void * args_voidp)
{
	const struct db_main_args * args = (const struct db_main_args *)args_voidp;

	if (args == NULL ||
		args->semaphore == NULL ||
		args->db_request_queue == NULL ||
		args->db_currently_processing == NULL)
	{
		LOG(LOG_ERR, "db thread called with NULL argument");
		pthread_exit(NULL);
	}

	run_state->semaphore = args->semaphore;
	run_state->db_request_queue = args->db_request_queue;
	run_state->db_currently_processing = args->db_currently_processing;
	run_state->db = NULL;

	run_state->request = NULL;
	run_state->request_state = NULL;

	run_state->response = NULL;
}


static void allocate_response(struct run_state * run_state, size_t num_pdus)
{
	if (run_state->response != NULL)
	{
		LOG(LOG_ERR, "allocate_response() called when there already is a response");
		pthread_exit(NULL);
	}

	run_state->response = malloc(sizeof(struct db_response));
	if (run_state->response == NULL)
	{
		LOG(LOG_ERR, "can't allocate memory for response");
		pthread_exit(NULL);
	}

	run_state->response->PDUs = (num_pdus == 0 ?
		NULL :
		malloc(sizeof(PDU) * num_pdus));
	run_state->response->num_PDUs = num_pdus;

	if (run_state->response->PDUs == NULL && num_pdus > 0)
	{
		LOG(LOG_ERR, "can't allocate memory for response PDUs");
		pthread_exit(NULL);
	}
}

static void send_response(struct run_state * run_state)
{
	if (!Queue_push(run_state->request_state->request->response_queue, (void *)run_state->response))
	{
		LOG(LOG_ERR, "can't push response to queue");
		pthread_exit(NULL);
	}

	run_state->response = NULL;

	if (sem_post(run_state->request_state->request->response_semaphore) != 0)
	{
		ERR_LOG(errno, run_state->errorbuf, "sem_post()");
	}
}

static void send_empty_response(struct run_state * run_state)
{
	allocate_response(run_state, 0);
	run_state->response->is_done = true;
	send_response(run_state);
}


static void send_error(struct run_state * run_state, error_code_t error_code)
{
	allocate_response(run_state, 1);

	run_state->response->is_done = true;

	run_state->response->PDUs[0].protocolVersion = RTR_PROTOCOL_VERSION;
	run_state->response->PDUs[0].pduType = PDU_ERROR_REPORT;
	run_state->response->PDUs[0].errorCode = error_code;
	run_state->response->PDUs[0].length = PDU_HEADER_LENGTH + PDU_ERROR_HEADERS_LENGTH;
	run_state->response->PDUs[0].errorData.encapsulatedPDULength = 0;
	run_state->response->PDUs[0].errorData.encapsulatedPDU = NULL;
	run_state->response->PDUs[0].errorData.errorTextLength = 0;
	run_state->response->PDUs[0].errorData.errorText = NULL;

	send_response(run_state);
}


static void wait_on_semaphore(struct run_state * run_state)
{
	if (sem_wait(run_state->semaphore) != 0)
	{
		ERR_LOG(errno, run_state->errorbuf, "sem_wait()");
		pthread_exit(NULL);
	}
}


/**
	Service run_state->request_state for exactly one step.

	If the request can't be finished, request_state gets put (back) in db_currently_processing.
*/
static void service_request(struct run_state * run_state, bool is_new_request)
{
	if (run_state->request_state->request->cancel_request)
	{
		stop_query(run_state->request_state, run_state->db);

		send_empty_response(run_state);

		free(run_state->request_state);
		run_state->request_state = NULL;
		return;
	}

	if (is_new_request)
	{
		int retval = start_query(run_state->request_state, run_state->db);
		// TODO: check for specific error codes
		if (retval != 0)
		{
			LOG(LOG_ERR, "error in start_query (error code %d)", retval);
			send_error(run_state, ERR_INTERNAL_ERROR);
			free(run_state->request_state);
			run_state->request_state = NULL;
			return;
		}
	}

	allocate_response(run_state, 0); // 0 because query_get_next() will allocate the PDUs

	bool is_done;
	ssize_t retval = query_get_next(run_state->request_state, run_state->db,
		DB_ROWS_PER_RESPONSE, &run_state->response->PDUs, &is_done);

	if (retval < 0)
	{
		is_done = true; // TODO: handle non-fatal errors?
		free(run_state->response);
		run_state->response = NULL;
	}
	else
	{
		run_state->response->is_done = is_done;
		run_state->response->num_PDUs = (size_t)retval;
	}

	if (is_done || retval < 0)
	{
		stop_query(run_state->request_state, run_state->db);
	}

	if (retval < 0)
	{
		// TODO: check for specific error codes
		LOG(LOG_ERR, "error in query_get_next (error code %zd)", retval);
		send_error(run_state, ERR_INTERNAL_ERROR);
		free(run_state->request_state);
		run_state->request_state = NULL;
		return;
	}

	send_response(run_state);

	if (is_done)
	{
		free(run_state->request_state);
		run_state->request_state = NULL;
	}
	else
	{
		if (!Bag_add(run_state->db_currently_processing, (void *)run_state->request_state))
		{
			LOG(LOG_ERR, "can't add a request state to the currently processing bag");
			stop_query(run_state->request_state, run_state->db);
			send_error(run_state, ERR_INTERNAL_ERROR);
			free(run_state->request_state);
			run_state->request_state = NULL;
			return;
		}

		run_state->request_state = NULL;

		/*
			NOTE: after putting the request back in db_currently_processing
			db_semaphore should be incremented to prevent problems in the below case:

			1. DB Thread 1: take CXN Thread 1's request out of db_currently_processing
				and start servicing it
			2. CXN Thread 1: take a previous response out if its response queue
				and increment db_semaphore
			3. DB Thread 2: decrement db_semaphore, do nothing because it can't see
				CXN Thread 1's request because DB Thread 1 has it
			4. DB Thread 1: finish servicing CXN Thread 1's request and put it back
				in db_currently_processing
		*/

		if (sem_post(run_state->semaphore) != 0)
		{
			ERR_LOG(errno, run_state->errorbuf, "sem_post()");
		}
	}
}


// Postcondition: run_state->request_state is non-NULL iff there is a request to service
static void find_existing_request_to_service(struct run_state * run_state)
{
	Bag_iterator it;
	bool did_erase;

	if (!Bag_start_iteration(run_state->db_currently_processing))
	{
		LOG(LOG_ERR, "error in Bag_start_iteration(run_state->db_currently_processing)");
		pthread_exit(NULL);
	}
	for (it = Bag_begin(run_state->db_currently_processing);
		it != Bag_end(run_state->db_currently_processing);
		(void)(did_erase || (it = Bag_iterator_next(run_state->db_currently_processing, it))))
	{
		did_erase = false;

		run_state->request_state = (struct db_request_state *)
			Bag_get(run_state->db_currently_processing, it);

		if (run_state->request_state == NULL)
		{
			LOG(LOG_ERR, "got NULL request state");
			it = Bag_erase(run_state->db_currently_processing, it);
			did_erase = true;
			continue;
		}

		if (run_state->request_state->request->cancel_request ||
			Queue_size(run_state->request_state->request->response_queue) < DB_RESPONSE_BUFFER_LENGTH)
		{
			it = Bag_erase(run_state->db_currently_processing, it);
			did_erase = true;
			if (!Bag_stop_iteration(run_state->db_currently_processing))
			{
				LOG(LOG_ERR, "error in Bag_stop_iteration(run_state->db_currently_processing)");
				pthread_exit(NULL);
			}
			return;
		}
	}
	if (!Bag_stop_iteration(run_state->db_currently_processing))
	{
		LOG(LOG_ERR, "error in Bag_stop_iteration(run_state->db_currently_processing)");
		pthread_exit(NULL);
	}

	// if control reaches here, there are no existing requests to service
	run_state->request_state = NULL;
}

static bool try_service_existing_request(struct run_state * run_state)
{
	find_existing_request_to_service(run_state);

	if (run_state->request_state == NULL)
	{
		return false;
	}
	else
	{
		service_request(run_state, false);
		return true;
	}
}


static bool try_service_new_request(struct run_state * run_state)
{
	if (!Queue_trypop(run_state->db_request_queue, (void**)&run_state->request))
		return false;

	run_state->request_state = malloc(sizeof(struct db_request_state));
	if (run_state->request_state == NULL)
	{
		LOG(LOG_ERR, "can't allocate memory for request state");
		pthread_exit(NULL);
	}

	initialize_request_state(run_state->request_state, run_state->request);
	run_state->request = NULL;

	service_request(run_state, true);

	return true;
}


static void db_main_loop(struct run_state * run_state)
{
	int retval, oldstate;

	wait_on_semaphore(run_state);

	if (run_state->request != NULL ||
		run_state->request_state != NULL ||
		run_state->response != NULL)
	{
		LOG(LOG_ERR, "got non-NULL state variable that should be NULL");
		pthread_exit(NULL);
	}

	retval = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
	if (retval != 0)
	{
		ERR_LOG(retval, run_state->errorbuf, "pthread_setcancelstate()");
	}

	if (try_service_existing_request(run_state)) return;
	if (try_service_new_request(run_state)) return;

	retval = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	if (retval != 0)
	{
		ERR_LOG(retval, run_state->errorbuf, "pthread_setcancelstate()");
	}
}



static void cleanup(void * run_state_voidp)
{
	struct run_state * run_state = (struct run_state *)run_state_voidp;

	if (run_state->db != NULL)
	{
		disconnectDb(run_state->db);
		run_state->db = NULL;
	}

	/* Unfortunately there doesn't seem to be a better option for
	request, request_state, and response than letting their memory
	be potentially lost. This is mitigated by making the thread
	not cancelable when their values are non-null. */
}


void * db_main(void * args_voidp)
{
	struct run_state run_state;

	initialize_run_state(&run_state, args_voidp);

	pthread_cleanup_push(cleanup, &run_state);

	run_state.db = connectDbDefault();
	if (run_state.db == NULL)
	{
		LOG(LOG_ERR, "can't connect to database");
		pthread_exit(NULL);
	}

	while (true)
	{
		db_main_loop(&run_state);
	}

	pthread_cleanup_pop(1);
}
