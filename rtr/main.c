#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "logutils.h"
#include "bag.h"
#include "queue.h"

#include "cache_state.h"
#include "config.h"
#include "common.h"

#include "db.h"
#include "connection_control.h"


#define LOG_PREFIX "[main ] "

// this is ok because there's only one main thread
static char errorbuf[ERROR_BUF_SIZE];


static bool create_db_thread(Bag * db_threads, struct db_main_args * db_main_args)
{
	if (db_threads == NULL ||
		db_main_args == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "create_db_thread() got NULL argument");
		return false;
	}

	int retval;

	pthread_t * thread = malloc(sizeof(pthread_t));
	if (thread == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't allocate memory for db thread id");
		return false;
	}

	retval = pthread_create(thread, NULL, db_main, (void *)db_main_args);
	if (retval != 0)
	{
		log_error(retval, errorbuf, LOG_PREFIX "in create_db_thread(): pthread_create()");
		free((void *)thread);
		return false;
	}

	if (!Bag_add(db_threads, (void *)thread))
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't add db thread id to bag");

		retval = pthread_cancel(*thread);
		if (retval != 0)
		{
			log_error(retval, errorbuf, LOG_PREFIX "in create_db_thread(): pthread_cancel()");
		}
		free((void *)thread);
		return false;
	}

	return true;
}

static void cancel_all_db_threads(Bag * db_threads)
{
	Bag_iterator it;
	int retval;
	pthread_t * thread;

	// TODO: join the threads after cancelling them

	Bag_start_iteration(db_threads);
	for (it = Bag_begin(db_threads);
		it != Bag_end(db_threads);
		it = Bag_erase(db_threads, it))
	{
		thread = Bag_get(db_threads, it);

		if (thread == NULL)
		{
			log_msg(LOG_ERR, LOG_PREFIX "got NULL thread id pointer");
			continue;
		}

		retval = pthread_cancel(*thread);
		if (retval != 0)
		{
			log_error(retval, errorbuf, LOG_PREFIX "in cancel_all_db_threads(): pthread_cancel()");
		}

		free((void *)thread);
	}
	Bag_stop_iteration(db_threads);
}


int main (int argc, char ** argv)
{
	ssize_t i;
	int retval1;

	(void)argc;
	(void)argv;

	if (log_init(LOG_FILE, LOG_FACILITY, LOG_DEBUG, LOG_DEBUG) != 0)
	{
		perror("log_init()");
		goto err;
	}

	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd == -1)
	{
		log_error(errno, errorbuf, LOG_PREFIX "socket()");
		goto err_log;
	}

	struct sockaddr_in bind_addr;
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_port = htons(LISTEN_PORT);
	bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(listen_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0)
	{
		log_error(errno, errorbuf, LOG_PREFIX "bind()");
		goto err_listen_fd;
	}

	if (listen(listen_fd, INT_MAX) != 0)
	{
		log_error(errno, errorbuf, LOG_PREFIX "listen()");
		goto err_listen_fd;
	}

	Queue * db_request_queue = Queue_new(true);
	if (db_request_queue == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't create db_request_queue");
		goto err_listen_fd;
	}

	Bag * db_currently_processing = Bag_new(true);
	if (db_currently_processing == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't create db_currently_processing");
		goto err_db_request_queue;
	}

	db_semaphore_t * db_semaphore = malloc(sizeof(db_semaphore_t));
	if (db_semaphore == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't allocate space for db_semaphore");
		goto err_db_currently_processing;
	}

	if (sem_init(db_semaphore, 0, 0) != 0)
	{
		log_error(errno, errorbuf, LOG_PREFIX "sem_init() for db_semaphore");
		goto err_db_seamphore_malloc;
	}

	struct global_cache_state global_cache_state;
	if (!initialize_global_cache_state(&global_cache_state))
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't initialize global cache state");
		goto err_db_semaphore_init;
	}

	Bag * db_threads = Bag_new(false);
	if (db_threads == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't create db_threads");
		goto err_global_cache_state_init;
	}

	struct db_main_args db_main_args;
	db_main_args.semaphore = db_semaphore;
	db_main_args.db_request_queue = db_request_queue;
	db_main_args.db_currently_processing = db_currently_processing;

	for (i = 0; i < DB_INITIAL_THREADS; ++i)
	{
		if (!create_db_thread(db_threads, &db_main_args))
		{
			log_msg(LOG_ERR, LOG_PREFIX "error creating db thread");
			goto err_db_threads;
		}
	}

	struct connection_control_main_args * connection_control_main_args = malloc(sizeof(struct connection_control_main_args));
	if (connection_control_main_args == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't allocate memory for connection_control_main_args");
		goto err_db_threads;
	}

	connection_control_main_args->listen_fd = listen_fd;
	connection_control_main_args->db_request_queue = db_request_queue;
	connection_control_main_args->db_semaphore = db_semaphore;
	connection_control_main_args->global_cache_state = &global_cache_state;

	pthread_t connection_control_thread;
	retval1 = pthread_create(&connection_control_thread, NULL, connection_control_main, connection_control_main_args);
	if (retval1 != 0)
	{
		log_error(retval1, errorbuf, LOG_PREFIX "creating connection control thread");
		free((void *)connection_control_main_args);
		goto err_db_threads;
	}

	while (true)
	{
		sleep(MAIN_LOOP_INTERVAL);

		// TODO: Check the load on the database threads, adding or removing threads as needed.

		if (!update_global_cache_state(&global_cache_state))
		{
			log_msg(LOG_NOTICE, LOG_PREFIX "error updating global cache state");
		}
	}

	return EXIT_SUCCESS;

err_db_threads:
	cancel_all_db_threads(db_threads);
	Bag_free(db_threads);
err_global_cache_state_init:
	close_global_cache_state(&global_cache_state);
err_db_semaphore_init:
	if (sem_destroy(db_semaphore) != 0) log_error(errno, errorbuf, LOG_PREFIX "sem_destroy()");
err_db_seamphore_malloc:
	free((void *)db_semaphore);
err_db_currently_processing:
	Bag_free(db_currently_processing);
err_db_request_queue:
	Queue_free(db_request_queue);
err_listen_fd:
	if (close(listen_fd) != 0) log_error(errno, errorbuf, LOG_PREFIX "close(listen_fd)");
err_log:
	log_close();
err:
	return EXIT_FAILURE;
}
