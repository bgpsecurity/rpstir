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

#include "bag.h"
#include "queue.h"
#include "logging.h"
#include "mysql-c-api/connect.h"

#include "cache_state.h"
#include "config.h"
#include "signals.h"

#include "db.h"
#include "connection_control.h"


// this is ok because there's only one main thread
static char errorbuf[ERROR_BUF_SIZE];


static void signal_handler(int signal)
{
	LOG(LOG_NOTICE, "received signal %d", signal);

	pthread_exit(NULL);
}


struct run_state {
	bool log_opened;

	bool listen_fd_initialized;
	int listen_fd;

	Queue * db_request_queue;
	Bag * db_currently_processing;

	bool db_semaphore_initialized;
	db_semaphore_t db_semaphore;

	void * db;

	bool global_cache_state_initialized;
	struct global_cache_state global_cache_state;

	bool db_thread_initialized;
	pthread_t * db_thread;

	Bag * db_threads;

	bool connection_control_thread_initialized;
	pthread_t connection_control_thread;

	// the below members are initialized by startup() and are not involved in cleanup
	struct db_main_args db_main_args;
	struct connection_control_main_args connection_control_main_args;
};


static void initialize_run_state(struct run_state * run_state)
{
	run_state->log_opened = false;

	run_state->listen_fd_initialized = false;

	run_state->db_request_queue = NULL;
	run_state->db_currently_processing = NULL;

	run_state->db_semaphore_initialized = false;

	run_state->db = NULL;

	run_state->global_cache_state_initialized = false;

	run_state->db_thread_initialized = false;
	run_state->db_thread = NULL;

	run_state->db_threads = NULL;

	run_state->connection_control_thread_initialized = false;
}


static bool create_db_thread(struct run_state * run_state)
{
	// TODO: handle signals

	int retval;

	run_state->db_thread_initialized = false;
	run_state->db_thread = malloc(sizeof(pthread_t));
	if (run_state->db_thread == NULL)
	{
		LOG(LOG_ERR, "can't allocate memory for db thread id");
		return false;
	}

	retval = pthread_create(run_state->db_thread, NULL, db_main, &run_state->db_main_args);
	if (retval != 0)
	{
		ERR_LOG(retval, errorbuf, "pthread_create()");
		free(run_state->db_thread);
		run_state->db_thread = NULL;
		return false;
	}
	run_state->db_thread_initialized = true;

	if (!Bag_add(run_state->db_threads, run_state->db_thread))
	{
		LOG(LOG_ERR, "can't add db thread id to bag");

		retval = pthread_cancel(*run_state->db_thread);
		if (retval != 0)
		{
			ERR_LOG(retval, errorbuf, "pthread_cancel()");
		}

		retval = pthread_join(*run_state->db_thread, NULL);
		if (retval != 0)
		{
			ERR_LOG(retval, errorbuf, "pthread_join()");
		}

		run_state->db_thread_initialized = false;

		free(run_state->db_thread);
		run_state->db_thread = NULL;

		return false;
	}

	run_state->db_thread = NULL;
	run_state->db_thread_initialized = false;

	return true;
}

static void cancel_all_db_threads(Bag * db_threads)
{
	Bag_iterator it;
	int retval;
	pthread_t * thread;

	if (!Bag_start_iteration(db_threads))
	{
		LOG(LOG_ERR, "error in Bag_start_iteration(db_threads)");
		return;
	}
	for (it = Bag_begin(db_threads);
		it != Bag_end(db_threads);
		it = Bag_iterator_next(db_threads, it))
	{
		thread = Bag_get(db_threads, it);

		if (thread == NULL)
		{
			LOG(LOG_ERR, "got NULL thread id pointer");
			continue;
		}

		retval = pthread_cancel(*thread);
		if (retval != 0)
		{
			ERR_LOG(retval, errorbuf, "pthread_cancel()");
		}
	}
	for (it = Bag_begin(db_threads);
		it != Bag_end(db_threads);
		it = Bag_erase(db_threads, it))
	{
		thread = Bag_get(db_threads, it);

		if (thread == NULL)
			continue;

		retval = pthread_join(*thread, NULL);
		if (retval != 0)
		{
			ERR_LOG(retval, errorbuf, "pthread_join()");
		}

		free((void *)thread);
	}
	Bag_stop_iteration(db_threads); // return value doesn't really matter here
}


static void cleanup(void * run_state_voidp)
{
	struct run_state * run_state = (struct run_state *)run_state_voidp;
	int retval;

	if (run_state->connection_control_thread_initialized)
	{
		LOG(LOG_NOTICE, "Stopping connection control thread...");

		retval = pthread_cancel(run_state->connection_control_thread);
		if (retval != 0)
		{
			ERR_LOG(retval, errorbuf, "pthread_cancel(connection_control)");
		}

		retval = pthread_join(run_state->connection_control_thread, NULL);
		if (retval != 0)
		{
			ERR_LOG(retval, errorbuf, "pthread_join(connection_control)");
		}

		run_state->connection_control_thread_initialized = false;

		LOG(LOG_NOTICE, "... done stopping connection control thread");
	}

	if (run_state->db_threads != NULL)
	{
		LOG(LOG_NOTICE, "Stopping active db threads...");

		cancel_all_db_threads(run_state->db_threads);
		Bag_free(run_state->db_threads);
		run_state->db_threads = NULL;

		LOG(LOG_NOTICE, "... done stopping active db threads");
	}

	if (run_state->db_thread != NULL)
	{
		if (run_state->db_thread_initialized)
		{
			LOG(LOG_NOTICE, "Stopping inactive db thread...");

			retval = pthread_cancel(*run_state->db_thread);
			if (retval != 0)
			{
				ERR_LOG(retval, errorbuf, "pthread_cancel(db_thread)");
			}

			retval = pthread_join(*run_state->db_thread, NULL);
			if (retval != 0)
			{
				ERR_LOG(retval, errorbuf, "pthread_join(db_thread)");
			}

			run_state->db_thread_initialized = false;

			LOG(LOG_NOTICE, "... done stopping inactive db thread");
		}

		free(run_state->db_thread);
		run_state->db_thread = NULL;
	}

	if (run_state->global_cache_state_initialized)
	{
		close_global_cache_state(&run_state->global_cache_state);
		run_state->global_cache_state_initialized = false;
	}

	if (run_state->db != NULL)
	{
		disconnectDb(run_state->db);
		run_state->db = NULL;
	}

	if (run_state->db_semaphore_initialized)
	{
		if (sem_destroy(&run_state->db_semaphore) != 0)
			ERR_LOG(errno, errorbuf, "sem_destroy()");
		run_state->db_semaphore_initialized = false;
	}

	if (run_state->db_currently_processing != NULL)
	{
		Bag_free(run_state->db_currently_processing);
		run_state->db_currently_processing = NULL;
	}

	if (run_state->db_request_queue != NULL)
	{
		Queue_free(run_state->db_request_queue);
		run_state->db_request_queue = NULL;
	}

	if (run_state->listen_fd_initialized)
	{
		if (close(run_state->listen_fd) != 0)
			ERR_LOG(errno, errorbuf, "close(listen_fd)");
		run_state->listen_fd_initialized = false;
	}

	LOG(LOG_NOTICE, "shutting down");

	if (run_state->log_opened)
	{
		CLOSE_LOG();
		run_state->log_opened = false;
	}
}


static void startup(struct run_state * run_state)
{
	// TODO: block signals at some key points to ensure run_state
	// always has pointers to all threads

	int retval, i;

	OPEN_LOG(RTR_LOG_IDENT, RTR_LOG_FACILITY);
	run_state->log_opened = true;

	run_state->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (run_state->listen_fd == -1)
	{
		ERR_LOG(errno, errorbuf, "socket()");
		pthread_exit(NULL);
	}
	run_state->listen_fd_initialized = true;

	struct sockaddr_in bind_addr;
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_port = htons(LISTEN_PORT);
	bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(run_state->listen_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0)
	{
		ERR_LOG(errno, errorbuf, "bind()");
		pthread_exit(NULL);
	}

	if (listen(run_state->listen_fd, INT_MAX) != 0)
	{
		ERR_LOG(errno, errorbuf, "listen()");
		pthread_exit(NULL);
	}

	run_state->db_request_queue = Queue_new(true);
	if (run_state->db_request_queue == NULL)
	{
		LOG(LOG_ERR, "can't create db_request_queue");
		pthread_exit(NULL);
	}

	run_state->db_currently_processing = Bag_new(true);
	if (run_state->db_currently_processing == NULL)
	{
		LOG(LOG_ERR, "can't create db_currently_processing");
		pthread_exit(NULL);
	}

	if (sem_init(&run_state->db_semaphore, 0, 0) != 0)
	{
		ERR_LOG(errno, errorbuf, "sem_init() for db_semaphore");
		pthread_exit(NULL);
	}
	run_state->db_semaphore_initialized = true;

	run_state->db = connectDbDefault();
	if (run_state->db == NULL)
	{
		LOG(LOG_ERR, "can't connect to database");
		pthread_exit(NULL);
	}

	if (!initialize_global_cache_state(&run_state->global_cache_state, run_state->db))
	{
		LOG(LOG_ERR, "can't initialize global cache state");
		pthread_exit(NULL);
	}
	run_state->global_cache_state_initialized = true;

	run_state->db_threads = Bag_new(false);
	if (run_state->db_threads == NULL)
	{
		LOG(LOG_ERR, "can't create db_threads");
		pthread_exit(NULL);
	}

	run_state->db_main_args.semaphore = &run_state->db_semaphore;
	run_state->db_main_args.db_request_queue = run_state->db_request_queue;
	run_state->db_main_args.db_currently_processing = run_state->db_currently_processing;

	for (i = 0; i < DB_INITIAL_THREADS; ++i)
	{
		if (!create_db_thread(run_state))
		{
			LOG(LOG_ERR, "error creating db thread");
			pthread_exit(NULL);
		}
	}

	run_state->connection_control_main_args.listen_fd = run_state->listen_fd;
	run_state->connection_control_main_args.db_request_queue = run_state->db_request_queue;
	run_state->connection_control_main_args.db_semaphore = &run_state->db_semaphore;
	run_state->connection_control_main_args.global_cache_state = &run_state->global_cache_state;

	retval = pthread_create(&run_state->connection_control_thread, NULL,
		connection_control_main, &run_state->connection_control_main_args);
	if (retval != 0)
	{
		ERR_LOG(retval, errorbuf, "pthread_create() for connection control thread");
		pthread_exit(NULL);
	}
	run_state->connection_control_thread_initialized = true;
}


int main (int argc, char ** argv)
{
	(void)argc;
	(void)argv;

	struct run_state run_state;
	initialize_run_state(&run_state);

	pthread_cleanup_push(cleanup, &run_state);

	handle_signals(signal_handler);

	startup(&run_state);

	while (true)
	{
		sleep(MAIN_LOOP_INTERVAL);

		// TODO: Check the load on the database threads, adding or removing threads as needed.

		if (!update_global_cache_state(&run_state.global_cache_state, run_state.db))
		{
			LOG(LOG_NOTICE, "error updating global cache state");
		}
	}

	pthread_cleanup_pop(1);

	return EXIT_FAILURE;
}
