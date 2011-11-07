#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include "logutils.h"

#include "connection_control.h"
#include "connection.h"


#define LOG_PREFIX "[connection control] "

// TODO: setup pthread cleanup functions so main can cancel us cleanly

struct connection_info {
	int fd;
	cxn_semaphore_t * semaphore;
	pthread_t thread;
};


static void log_error(int err, char const * prefix)
{
	// static is ok because it's only used from one thread
	static char errorbuf[1024];

	if (strerror_r(err, errorbuf, 1024) == 0)
	{
		log_msg(LOG_ERR, LOG_PREFIX "%s: %s", prefix, errorbuf);
	}
	else
	{
		log_msg(LOG_ERR, LOG_PREFIX "%s: error code %d", prefix, err);
	}
}


static void kill_connection(struct connection_info * cxn_info)
{
	assert(cxn_info != NULL);

	int retval1, retval2;

	retval1 = pthread_cancel(cxn_info->thread);
	if (retval1 == 0)
	{
		retval2 = pthread_join(cxn_info->thread, NULL);
		if (retval2 != 0)
			log_error(retval2, "pthread_join()");
	}
	else if (retval1 != ESRCH)
	{
		log_msg(LOG_ERR, LOG_PREFIX "unknown error code from pthread_cancel: %d", retval1);
	}
}

static void cleanup_connection(struct connection_info * cxn_info)
{
	assert(cxn_info != NULL);

	int retval1;

	retval1 = close(cxn_info->fd);
	if (retval1 != 0)
		log_error(retval1, "close()");

	retval1 = sem_destroy(cxn_info->semaphore);
	if (retval1 != 0)
		log_error(retval1, "sem_destroy()");

	free((void *)cxn_info->semaphore);
	free((void *)cxn_info);
}


void * connection_control_main(void * args_voidp)
{
	struct connection_control_main_args * argsp = (struct connection_control_main_args *) args_voidp;

	assert(argsp != NULL);

	int retval;

	Bag * connections = Bag_new(false);
	if (connections == NULL)
	{
		log_msg(LOG_ERR, LOG_PREFIX "error creating Bag of connection info");
		return NULL;
	}

	Bag_iterator connections_it;

	fd_set read_fds;
	int nfds;

	bool did_erase;

	while (true)
	{
		FD_ZERO(&read_fds);
		nfds = 0;

		FD_SET(argsp->listen_fd, &read_fds);
		if (argsp->listen_fd + 1 > nfds) nfds = argsp->listen_fd + 1;

		Bag_start_iteration(connections);
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
		Bag_stop_iteration(connections);

		retval = select(nfds, &read_fds, NULL, NULL, NULL);

		if (retval < 0)
		{
			log_error(errno, "select()");
			continue;
		}
		else if (retval == 0)
		{
			log_msg(LOG_ERR, LOG_PREFIX "select() returned even though there was no activity");
			continue;
		}

		Bag_start_iteration(connections);
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
					log_error(errno, "sem_post()");
					kill_connection(cxn_info);
					cleanup_connection(cxn_info);
					connections_it = Bag_erase(connections, connections_it);
					did_erase = true;
				}
			}
		}
		Bag_stop_iteration(connections);

		if (FD_ISSET(argsp->listen_fd, &read_fds))
		{
			struct connection_info * cxn_info = malloc(sizeof(struct connection_info));
			if (cxn_info == NULL)
			{
				log_msg(LOG_ERR, LOG_PREFIX "can't allocate memory for a new connection");
				continue;
			}

			cxn_info->semaphore = malloc(sizeof(cxn_semaphore_t));
			if (cxn_info->semaphore == NULL)
			{
				log_msg(LOG_ERR, LOG_PREFIX "can't allocate memory for a new connection semaphore");
				free((void *)cxn_info);
				continue;
			}

			if (sem_init(cxn_info->semaphore, 0, 0) != 0)
			{
				log_error(errno, "sem_init()");
				free((void *)cxn_info->semaphore);
				free((void *)cxn_info);
				continue;
			}

			cxn_info->fd = accept(argsp->listen_fd, NULL, NULL);
			if (cxn_info->fd < 0)
			{
				log_error(errno, "accept()");
				if (sem_destroy(cxn_info->semaphore) != 0)
				{
					log_error(errno, "sem_destroy()");
				}
				free((void *)cxn_info->semaphore);
				free((void *)cxn_info);
				continue;
			}

			struct connection_main_args * connection_args = malloc(sizeof(struct connection_main_args));
			if (connection_args == NULL)
			{
				log_msg(LOG_ERR, LOG_PREFIX "can't allocate memory for a new connection's arguments");
				cleanup_connection(cxn_info);
				continue;
			}

			connection_args->socket = cxn_info->fd;
			connection_args->semaphore = cxn_info->semaphore;
			connection_args->db_request_queue = argsp->db_request_queue;
			connection_args->db_semaphores_all = argsp->db_semaphores_all;
			connection_args->global_cache_state = argsp->global_cache_state;

			retval = pthread_create(&cxn_info->thread, NULL, connection_main, (void *)connection_args);
			if (retval != 0)
			{
				log_error(retval, "pthread_create()");
				free((void *)connection_args);
				cleanup_connection(cxn_info);
				continue;
			}

			if (!Bag_add(connections, (void *)cxn_info))
			{
				log_msg(LOG_ERR, LOG_PREFIX "can't add new connection's information to the set of existing connections");
				cleanup_connection(cxn_info);
				continue;
			}

			log_msg(LOG_INFO, LOG_PREFIX "new connection"); // TODO remote socket information (e.g. host:port)
		}
	}
}
