#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#include "logging.h"

#include "signals.h"
#include "connection_control.h"
#include "connection.h"


struct connection_info {
	int fd;
	cxn_semaphore_t * semaphore;
	pthread_t thread;
	bool started;
};


// this is ok because there's only one connection control thread
static char errorbuf[ERROR_BUF_SIZE];


static void kill_connection(struct connection_info * cxn_info)
{
	assert(cxn_info != NULL);

	int retval1;

	retval1 = pthread_cancel(cxn_info->thread);
	if (retval1 != 0 && retval1 != ESRCH)
	{
		ERR_LOG(retval1, errorbuf, "pthread_cancel()");
	}
}

static void cleanup_connection(struct connection_info * cxn_info)
{
	assert(cxn_info != NULL);

	int retval1;

	if (cxn_info->started)
	{
		retval1 = pthread_join(cxn_info->thread, NULL);
		if (retval1 != 0)
			ERR_LOG(retval1, errorbuf, "pthread_join()");
	}

	retval1 = close(cxn_info->fd);
	if (retval1 != 0)
		ERR_LOG(errno, errorbuf, "close()");

	retval1 = sem_destroy(cxn_info->semaphore);
	if (retval1 != 0)
		ERR_LOG(errno, errorbuf, "sem_destroy()");

	free((void *)cxn_info->semaphore);
	free((void *)cxn_info);
}


static void cleanup(void * connections_voidp)
{
	Bag * connections = (Bag *)connections_voidp;

	if (connections == NULL)
	{
		LOG(LOG_ERR, "unexpected NULL pointer");
		return;
	}

	Bag_iterator it;
	struct connection_info * cxn_info;

	if (!Bag_start_iteration(connections))
	{
		LOG(LOG_ERR, "error in Bag_start_iteration(connections)");
	}
	for (it = Bag_begin(connections);
		it != Bag_end(connections);
		it = Bag_iterator_next(connections, it))
	{
		cxn_info = (struct connection_info *)Bag_get(connections, it);

		if (cxn_info == NULL)
		{
			LOG(LOG_ERR, "found NULL connection info");
			continue;
		}

		kill_connection(cxn_info);
	}
	for (it = Bag_begin(connections);
		it != Bag_end(connections);
		it = Bag_erase(connections, it))
	{
		cxn_info = (struct connection_info *)Bag_get(connections, it);

		if (cxn_info == NULL)
			continue;

		cleanup_connection(cxn_info);
	}
	if (!Bag_stop_iteration(connections))
	{
		LOG(LOG_ERR, "error in Bag_stop_iteration(connections)");
	}

	Bag_free(connections);
}


void * connection_control_main(void * args_voidp)
{
	block_signals();

	struct connection_control_main_args * argsp = (struct connection_control_main_args *) args_voidp;

	assert(argsp != NULL);

	int retval, retval2;
	int oldstate;

	Bag * connections = Bag_new(false);
	if (connections == NULL)
	{
		LOG(LOG_ERR, "error creating Bag of connection info");
		return NULL;
	}

	pthread_cleanup_push(cleanup, (void *)connections);

	Bag_iterator connections_it;

	struct timeval timeout;
	fd_set read_fds;
	int nfds;

	bool did_erase;

	retval = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
	if (retval != 0)
	{
		ERR_LOG(retval, errorbuf, "pthread_setcancelstate()");
	}

	while (true)
	{
		FD_ZERO(&read_fds);
		nfds = 0;

		FD_SET(argsp->listen_fd, &read_fds);
		if (argsp->listen_fd + 1 > nfds) nfds = argsp->listen_fd + 1;

		if (!Bag_start_iteration(connections))
		{
			LOG(LOG_ERR, "error in Bag_start_iteration(connections)");
			continue;
		}
		for (connections_it = Bag_begin(connections);
			connections_it != Bag_end(connections);
			(void)(did_erase || (connections_it = Bag_iterator_next(connections, connections_it))))
		{
			did_erase = false;

			struct connection_info * cxn_info = (struct connection_info *)Bag_get(connections, connections_it);

			assert(cxn_info != NULL);

			if (pthread_kill(cxn_info->thread, 0) == ESRCH)
			{
				cleanup_connection(cxn_info);
				connections_it = Bag_erase(connections, connections_it);
				did_erase = true;
				continue;
			}

			FD_SET(cxn_info->fd, &read_fds);
			if (cxn_info->fd + 1 > nfds) nfds = cxn_info->fd + 1;
		}
		Bag_stop_iteration(connections); // return value doesn't really matter here

		retval = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
		if (retval != 0)
		{
			ERR_LOG(retval, errorbuf, "pthread_setcancelstate()");
		}

		// One the thread has started in the loop, this is the only
		// place it can be canceled. This should be acceptable because
		// connection_control is designed to do very little in each
		// loop iteration and to never block on anything other than
		// select().

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		retval = select(nfds, &read_fds, NULL, NULL, &timeout);

		retval2 = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
		if (retval2 != 0)
		{
			ERR_LOG(retval2, errorbuf, "pthread_setcancelstate()");
		}

		if (retval < 0)
		{
			ERR_LOG(errno, errorbuf, "select()");
			continue;
		}
		else if (retval == 0)
		{
			continue;
		}

		if (!Bag_start_iteration(connections))
		{
			LOG(LOG_ERR, "error in Bag_start_iteration(connections)");
			continue;
		}
		for (connections_it = Bag_begin(connections);
			connections_it != Bag_end(connections);
			(void)(did_erase || (connections_it = Bag_iterator_next(connections, connections_it))))
		{
			did_erase = false;

			struct connection_info * cxn_info = (struct connection_info *)Bag_get(connections, connections_it);

			assert(cxn_info != NULL);

			if (FD_ISSET(cxn_info->fd, &read_fds))
			{
				if (sem_post(cxn_info->semaphore) != 0)
				{
					ERR_LOG(errno, errorbuf, "sem_post()");
					kill_connection(cxn_info);
					cleanup_connection(cxn_info);
					connections_it = Bag_erase(connections, connections_it);
					did_erase = true;
				}
			}
		}
		Bag_stop_iteration(connections); // return value doesn't really matter here

		if (FD_ISSET(argsp->listen_fd, &read_fds))
		{
			struct connection_info * cxn_info = malloc(sizeof(struct connection_info));
			if (cxn_info == NULL)
			{
				LOG(LOG_ERR, "can't allocate memory for a new connection");
				continue;
			}

			cxn_info->started = false;

			cxn_info->semaphore = malloc(sizeof(cxn_semaphore_t));
			if (cxn_info->semaphore == NULL)
			{
				LOG(LOG_ERR, "can't allocate memory for a new connection semaphore");
				free((void *)cxn_info);
				continue;
			}

			if (sem_init(cxn_info->semaphore, 0, 0) != 0)
			{
				ERR_LOG(errno, errorbuf, "sem_init()");
				free((void *)cxn_info->semaphore);
				free((void *)cxn_info);
				continue;
			}

			cxn_info->fd = accept(argsp->listen_fd, NULL, NULL);
			if (cxn_info->fd < 0)
			{
				ERR_LOG(errno, errorbuf, "accept()");
				if (sem_destroy(cxn_info->semaphore) != 0)
				{
					ERR_LOG(errno, errorbuf, "sem_destroy()");
				}
				free((void *)cxn_info->semaphore);
				free((void *)cxn_info);
				continue;
			}

			struct connection_main_args * connection_args = malloc(sizeof(struct connection_main_args));
			if (connection_args == NULL)
			{
				LOG(LOG_ERR, "can't allocate memory for a new connection's arguments");
				cleanup_connection(cxn_info);
				continue;
			}

			connection_args->socket = cxn_info->fd;
			connection_args->semaphore = cxn_info->semaphore;
			connection_args->db_request_queue = argsp->db_request_queue;
			connection_args->db_semaphore = argsp->db_semaphore;
			connection_args->global_cache_state = argsp->global_cache_state;

			retval = pthread_create(&cxn_info->thread, NULL, connection_main, (void *)connection_args);
			if (retval != 0)
			{
				ERR_LOG(retval, errorbuf, "pthread_create()");
				free((void *)connection_args);
				cleanup_connection(cxn_info);
				continue;
			}
			cxn_info->started = true;

			if (!Bag_add(connections, (void *)cxn_info))
			{
				LOG(LOG_ERR, "can't add new connection's information to the set of existing connections");
				cleanup_connection(cxn_info);
				continue;
			}

			LOG(LOG_INFO, "new connection"); // TODO remote socket information (e.g. host:port)
		}
	}

	pthread_cleanup_pop(1);
}
