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


#define LOG_PREFIX "[main ]"

// this is ok because there's only one main thread
static char errorbuf[ERROR_BUF_SIZE];


static bool create_db_thread(Queue * db_request_queue, Bag * db_semaphores_all)
{
	if (db_request_queue == NULL || db_semaphores_all == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "create_db_thread() got NULL argument");
		return false;
	}

	int retval;

	struct db_main_args * args = malloc(sizeof(struct db_main_args));
	if (args == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't allocate memory for a db thread's arguments");
		return false;
	}

	args->db_request_queue = db_request_queue;

	args->semaphore = malloc(sizeof(db_semaphore_t));
	if (args->semaphore == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't allocate memory for a db semaphore");
		free((void *)args);
		return false;
	}


	if (sem_init(args->semaphore, 0, 0) != 0)
	{
		log_error(errno, errorbuf, LOG_PREFIX "in create_db_thread(): sem_init()");
		free((void *)args->semaphore);
		free((void *)args);
		return false;
	}

	if (!Bag_add(db_semaphores_all, (void *)args->semaphore))
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't add new db semaphore to db_semaphores_all");
		if (sem_destroy(args->semaphore) != 0) log_error(errno, errorbuf, LOG_PREFIX "in create_db_thread(): sem_destroy()");
		free((void *)args->semaphore);
		free((void *)args);
		return false;
	}

	pthread_t thread;
	retval = pthread_create(&thread, NULL, db_main, (void *)args);
	if (retval != 0)
	{
		log_error(retval, errorbuf, LOG_PREFIX "in create_db_thread(): pthread_create()");
		// TODO: remove args->semaphore from db_semaphores_all, destroy it, and free it
		free((void *)args);
		return false;
	}

	return true;
}

static void cancel_all_db_threads(/* TODO */)
{
	// TODO
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

	Bag * db_semaphores_all = Bag_new(true);
	if (db_semaphores_all == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't create db_semaphores_all");
		goto err_db_request_queue;
	}

	struct global_cache_state global_cache_state;
	if (!initialize_global_cache_state(&global_cache_state))
	{
		log_msg(LOG_ERR, LOG_PREFIX "can't initialize global cache state");
		goto err_db_semaphores_all;
	}

	for (i = 0; i < DB_INITIAL_THREADS; ++i)
	{
		if (!create_db_thread(db_request_queue, db_semaphores_all))
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
	connection_control_main_args->db_semaphores_all = db_semaphores_all;
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
	cancel_all_db_threads();
	close_global_cache_state(&global_cache_state);
err_db_semaphores_all:
	Bag_free(db_semaphores_all);
err_db_request_queue:
	Queue_free(db_request_queue);
err_listen_fd:
	if (close(listen_fd) != 0) log_error(errno, errorbuf, LOG_PREFIX "close(listen_fd)");
err_log:
	log_close();
err:
	return EXIT_FAILURE;
}
