#include "logutils.h"
#include "macros.h"

#include "db.h"


#define LOG_PREFIX "[db] "


// The below should work for a query like SELECT ... FROM ... WHERE serial = last_serial ORDER BY ... LIMIT last_row, ...
struct db_query_progress {
	serial_number_t last_serial;
	size_t last_row;
};

struct db_request_state {
	struct db_request * request;
	struct db_query_progress progress;
};


// after calling, pdus will be freed or passed along to a response queue
static bool send_response(const struct db_request * request, PDU * pdus, size_t num_pdus, db_semaphore_t * more_data_semaphore)
{
	struct db_response * response = malloc(sizeof(struct db_response));
	if (response == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't allocate memory for response");
		pdu_free_array(pdus, num_pdus);
		return false;
	}

	response->PDUs = pdus;
	response->num_PDUs = num_pdus;
	response->more_data_semaphore = more_data_semaphore;

	if (!Queue_push(request->response_queue, (void *)response))
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't push response to queue");
		pdu_free_array(response->PDUs, response->num_PDUs);
		free((void *)response);
		return false;
	}

	if (sem_post(request->response_semaphore) != 0)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't post to the response semaphore");
		return false;
	}

	return true;
}


static bool send_error(const struct db_request * request, error_code_t error_code, db_semaphore_t * more_data_semaphore)
{
	PDU * pdu = malloc(sizeof(PDU));
	if (pdu == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't allocate memory for response error PDU");
		return false;
	}

	pdu->protocolVersion = PROTOCOL_VERSION;
	pdu->pduType = PDU_ERROR_REPORT;
	pdu->errorCode = error_code;
	pdu->length = PDU_HEADER_LENGTH + PDU_ERROR_HEADERS_LENGTH;
	pdu->errorData.encapsulatedPDULength = 0;
	pdu->errorData.encapsulatedPDU = NULL;
	pdu->errorData.errorTextLength = 0;
	pdu->errorData.errorText = NULL;

	return send_response(request, pdu, 1, more_data_semaphore);
}


static void cancel_all(Bag * currently_processing)
{
	if (currently_processing == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "got NULL currently_processing");
		return;
	}

	Bag_iterator it;
	struct db_request_state * request_state;

	Bag_start_iteration(currently_processing);
	for (it = Bag_begin(currently_processing);
		it != Bag_end(currently_processing);
		it = Bag_erase(currently_processing, it))
	{
		request_state = (struct db_request_state *)Bag_get(currently_processing, it);

		if (request_state == NULL)
		{
			log_msg(LOG_ERR, LOG_PREFIX "got NULL request state");
			continue;
		}

		send_error(request_state->request, ERR_INTERNAL_ERROR, NULL);

		free((void *)request_state);
	}
	Bag_stop_iteration(currently_processing);
}


void * db_main(void * args_voidp)
{
	struct db_main_args * argsp = (struct db_main_args *)args_voidp;

	if (argsp == NULL || argsp->semaphore == NULL || argsp->db_request_queue == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "received NULL argument");
		return NULL;
	}

	Bag * currently_processing = Bag_new(false);

	if (currently_processing == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't create currently_processing bag");
		return NULL;
	}

	bool operation_completed;
	bool did_erase;
	Bag_iterator it;
	struct db_request * request;
	struct db_request_state * request_state;

	while (true)
	{
		if (sem_wait(argsp->semaphore) != 0)
		{
			cancel_all(currently_processing);
			Bag_free(currently_processing);
			// XXX: DB threads can still have access to argsp->semaphore in their response queues
			return NULL;
		}

		operation_completed = false;

		Bag_start_iteration(currently_processing);
		for (it = Bag_begin(currently_processing);
			it != Bag_end(currently_processing);
			(void)(did_erase || (it = Bag_iterator_next(currently_processing, it))))
		{
			did_erase = false;

			request_state = (struct db_request_state *)Bag_get(currently_processing, it);

			if (request_state == NULL)
			{
				log_msg(LOG_ERR, LOG_PREFIX "got NULL request state");
				continue;
			}

			if (request_state->request->cancel_request)
			{
				if (!send_response(request_state->request, NULL, 0, NULL))
				{
					log_msg(LOG_ERR, LOG_PREFIX "can't acknowledge a canceled request");
				}

				free((void *)request_state);

				it = Bag_erase(currently_processing, it);
				did_erase = true;

				operation_completed = true;
				break;
			}

			// TODO
		}
		Bag_stop_iteration(currently_processing);

		if (!operation_completed && Queue_trypop(argsp->db_request_queue, (void**)&request))
		{
			// FIXME/TODO: real implementation instead of this stub
			if (request == NULL)
			{
				log_msg(LOG_ERR, LOG_PREFIX "got NULL db request");
			}
			else
			{
				if (!send_error(request, ERR_INTERNAL_ERROR, NULL))
					log_msg(LOG_ERR, LOG_PREFIX "couldn't send error");
			}
		}
	}
}
