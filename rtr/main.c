#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <netdb.h>

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
static int exit_code = EXIT_SUCCESS;


// NOTE: you must call block_signals() before any call to pthread_exit() that's
// outside of signal_handler(), to prevent duplicate calls to pthread_exit().
static void signal_handler(int signal)
{
	LOG(LOG_NOTICE, "received signal %d", signal);

	pthread_exit(NULL);
}


struct run_state {
	bool log_opened;

	size_t listen_fds_initialized;
	int listen_fds[MAX_LISTENING_SOCKETS];

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

	run_state->listen_fds_initialized = 0;

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


static void make_listen_sockets(struct run_state * run_state,
	const char * node, const char * service)
{
	int retval;
	struct addrinfo hints, *res, *resp;
	char listen_host[MAX_HOST_LENGTH];
	char listen_serv[MAX_SERVICE_LENGTH];

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_addrlen = 0;
	hints.ai_addr = NULL;
	hints.ai_canonname = NULL;
	hints.ai_next = NULL;

	block_signals();
	retval = getaddrinfo(node, service, &hints, &res);
	if (retval != 0)
	{
		LOG(LOG_ERR, "getaddrinfo() on node \"%s\" port \"%s\": %s",
			(node == NULL ? "(any)" : node),
			(service == NULL ? "(any)" : service),
			gai_strerror(retval));
		exit_code = EXIT_FAILURE;
		pthread_exit(NULL);
	}

	for (resp = res; resp != NULL; resp = resp->ai_next)
	{
		if (run_state->listen_fds_initialized >= MAX_LISTENING_SOCKETS)
		{
			LOG(LOG_ERR, "can't listen on more than %d sockets, "
				"increase the limit in rtr/config.h if needed",
				MAX_LISTENING_SOCKETS);
			freeaddrinfo(res);
			exit_code = EXIT_FAILURE;
			pthread_exit(NULL);
		}

		run_state->listen_fds[run_state->listen_fds_initialized] =
			socket(resp->ai_family, resp->ai_socktype, resp->ai_protocol);
		if (run_state->listen_fds[run_state->listen_fds_initialized] == -1)
		{
			ERR_LOG(errno, errorbuf, "socket()");
			freeaddrinfo(res);
			exit_code = EXIT_FAILURE;
			pthread_exit(NULL);
		}
		++run_state->listen_fds_initialized;

		if (resp->ai_family == AF_INET6)
		{
			// prevent AF_INET6 sockets from contending with AF_INET sockets
			int optval = true;
			if (setsockopt(run_state->listen_fds[run_state->listen_fds_initialized - 1],
				IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(optval)) != 0)
			{
				ERR_LOG(errno, errorbuf, "setsockopt()");
			}
		}

		retval = getnameinfo(resp->ai_addr, resp->ai_addrlen,
			listen_host, sizeof(listen_host),
			listen_serv, sizeof(listen_serv),
			NI_NUMERICHOST | NI_NUMERICSERV);
		if (retval != 0)
		{
			LOG(LOG_ERR, "getnameinfo(): %s", gai_strerror(retval));
			freeaddrinfo(res);
			exit_code = EXIT_FAILURE;
			pthread_exit(NULL);
		}

		if (bind(run_state->listen_fds[run_state->listen_fds_initialized - 1],
			resp->ai_addr, resp->ai_addrlen) != 0)
		{
			ERR_LOG(errno, errorbuf, "bind([%s]:%s)", listen_host, listen_serv);
			freeaddrinfo(res);
			exit_code = EXIT_FAILURE;
			pthread_exit(NULL);
		}

		if (listen(run_state->listen_fds[run_state->listen_fds_initialized - 1],
			INT_MAX) != 0)
		{
			ERR_LOG(errno, errorbuf, "listen([%s]:%s)", listen_host, listen_serv);
			freeaddrinfo(res);
			exit_code = EXIT_FAILURE;
			pthread_exit(NULL);
		}

		LOG(LOG_INFO, "listening on [%s]:%s", listen_host, listen_serv);
	}

	freeaddrinfo(res);

	unblock_signals();
}


static bool create_db_thread(struct run_state * run_state)
{
	int retval;

	block_signals();
	run_state->db_thread_initialized = false;
	run_state->db_thread = malloc(sizeof(pthread_t));
	unblock_signals();
	if (run_state->db_thread == NULL)
	{
		LOG(LOG_ERR, "can't allocate memory for db thread id");
		return false;
	}

	block_signals();
	retval = pthread_create(run_state->db_thread, NULL, db_main, &run_state->db_main_args);
	run_state->db_thread_initialized = (retval == 0);
	if (retval != 0)
	{
		ERR_LOG(retval, errorbuf, "pthread_create()");
		free(run_state->db_thread);
		run_state->db_thread = NULL;
		unblock_signals();
		return false;
	}
	unblock_signals();

	block_signals();
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

		// Commented out because free and pointer assignment should be pretty fast,
		// so testing for signals is unnecessary here.
		//unblock_signals();
		//block_signals();

		free(run_state->db_thread);
		run_state->db_thread = NULL;

		unblock_signals();

		return false;
	}

	run_state->db_thread = NULL;
	run_state->db_thread_initialized = false;

	unblock_signals();

	return true;
}

// NOTE: this does not do signal handling, so it can only be called when signals
// are already blocked, e.g. in cleanup().
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

		LOG(LOG_DEBUG, "about to cancel db thread");

		retval = pthread_cancel(*thread);
		if (retval != 0)
		{
			ERR_LOG(retval, errorbuf, "pthread_cancel()");
		}

		LOG(LOG_DEBUG, "after cancel db thread");
	}
	for (it = Bag_begin(db_threads);
		it != Bag_end(db_threads);
		it = Bag_erase(db_threads, it))
	{
		thread = Bag_get(db_threads, it);

		if (thread == NULL)
			continue;

		LOG(LOG_DEBUG, "about to join db thread");

		retval = pthread_join(*thread, NULL);
		if (retval != 0)
		{
			ERR_LOG(retval, errorbuf, "pthread_join()");
		}

		LOG(LOG_DEBUG, "after join db thread");

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
		LOG(LOG_DEBUG, "done cancel_all_db_threads");
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
		db_disconnect(run_state->db);
		run_state->db = NULL;
		db_thread_close();
		db_close();
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

	for (; run_state->listen_fds_initialized > 0; --run_state->listen_fds_initialized)
	{
		if (close(run_state->listen_fds[run_state->listen_fds_initialized - 1]) != 0)
			ERR_LOG(errno, errorbuf, "close()");
	}

	LOG(LOG_NOTICE, "shutting down");

	if (run_state->log_opened)
	{
		CLOSE_LOG();
		run_state->log_opened = false;
	}

	// main should be the only thread left at this point, but just in case:
	exit(exit_code);
}


static void startup(struct run_state * run_state)
{
	int retval, i;

	block_signals();
	OPEN_LOG(RTR_LOG_IDENT, RTR_LOG_FACILITY);
	run_state->log_opened = true;
	unblock_signals();

	make_listen_sockets(run_state, NULL, LISTEN_PORT);

	if (run_state->listen_fds_initialized <= 0)
	{
		LOG(LOG_ERR, "no sockets to listen on");
		block_signals();
		exit_code = EXIT_FAILURE;
		pthread_exit(NULL);
	}

	block_signals();
	run_state->db_request_queue = Queue_new(true);
	if (run_state->db_request_queue == NULL)
	{
		LOG(LOG_ERR, "can't create db_request_queue");
		exit_code = EXIT_FAILURE;
		pthread_exit(NULL);
	}
	unblock_signals();

	block_signals();
	run_state->db_currently_processing = Bag_new(true);
	if (run_state->db_currently_processing == NULL)
	{
		LOG(LOG_ERR, "can't create db_currently_processing");
		exit_code = EXIT_FAILURE;
		pthread_exit(NULL);
	}
	unblock_signals();

	block_signals();
	if (sem_init(&run_state->db_semaphore, 0, 0) != 0)
	{
		ERR_LOG(errno, errorbuf, "sem_init() for db_semaphore");
		exit_code = EXIT_FAILURE;
		pthread_exit(NULL);
	}
	run_state->db_semaphore_initialized = true;
	unblock_signals();

	block_signals();
	if (!db_init())
	{
		LOG(LOG_ERR, "can't initialize global DB state");
		exit_code = EXIT_FAILURE;
		pthread_exit(NULL);
	}
	if (!db_thread_init())
	{
		LOG(LOG_ERR, "can't initialize thread-local DB state");
		db_close();
		exit_code = EXIT_FAILURE;
		pthread_exit(NULL);
	}
	run_state->db = db_connect_default(DB_CLIENT_RTR);
	if (run_state->db == NULL)
	{
		LOG(LOG_ERR, "can't connect to database");
		db_thread_close();
		db_close();
		exit_code = EXIT_FAILURE;
		pthread_exit(NULL);
	}
	unblock_signals();

	block_signals();
	if (!initialize_global_cache_state(&run_state->global_cache_state, run_state->db))
	{
		LOG(LOG_ERR, "can't initialize global cache state");
		exit_code = EXIT_FAILURE;
		pthread_exit(NULL);
	}
	run_state->global_cache_state_initialized = true;
	unblock_signals();

	block_signals();
	run_state->db_threads = Bag_new(false);
	if (run_state->db_threads == NULL)
	{
		LOG(LOG_ERR, "can't create db_threads");
		exit_code = EXIT_FAILURE;
		pthread_exit(NULL);
	}
	unblock_signals();

	run_state->db_main_args.semaphore = &run_state->db_semaphore;
	run_state->db_main_args.db_request_queue = run_state->db_request_queue;
	run_state->db_main_args.db_currently_processing = run_state->db_currently_processing;

	for (i = 0; i < DB_INITIAL_THREADS; ++i)
	{
		if (!create_db_thread(run_state))
		{
			LOG(LOG_ERR, "error creating db thread");
			block_signals();
			exit_code = EXIT_FAILURE;
			pthread_exit(NULL);
		}
	}

	run_state->connection_control_main_args.listen_fds = run_state->listen_fds;
	run_state->connection_control_main_args.num_listen_fds = run_state->listen_fds_initialized;
	run_state->connection_control_main_args.db_request_queue = run_state->db_request_queue;
	run_state->connection_control_main_args.db_semaphore = &run_state->db_semaphore;
	run_state->connection_control_main_args.global_cache_state = &run_state->global_cache_state;

	block_signals();
	retval = pthread_create(&run_state->connection_control_thread, NULL,
		connection_control_main, &run_state->connection_control_main_args);
	if (retval != 0)
	{
		ERR_LOG(retval, errorbuf, "pthread_create() for connection control thread");
		exit_code = EXIT_FAILURE;
		pthread_exit(NULL);
	}
	run_state->connection_control_thread_initialized = true;
	unblock_signals();
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

		block_signals();
		if (!update_global_cache_state(&run_state.global_cache_state, run_state.db))
		{
			LOG(LOG_NOTICE, "error updating global cache state");
		}
		unblock_signals();
	}

	pthread_cleanup_pop(1);

	return EXIT_FAILURE;
}
