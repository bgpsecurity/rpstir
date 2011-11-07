#include <assert.h>
#include <sys/select.h>

#include "connection_control.h"
#include "connection.h"


struct connection_info {
	int fd;
	cxn_semaphore_t * semaphore;
	pthread_t thread;
};

void * connection_control_main(void * args_voidp)
{
	struct connection_control_main_args * argsp = (struct connection_control_main_args *) args_voidp;

	assert(argsp != NULL);

	Bag * connections = Bag_new(false);
	if (connections == NULL)
		return NULL;
	Bag_const_iterator connections_const_it;
	Bag_iterator connections_it;

	fd_set read_fds;
	int nfds;
	int select_retval;

	bool did_erase;

	while (true)
	{
		FD_ZERO(&read_fds);
		nfds = 0;

		FD_SET(argsp->listen_fd, &read_fds);
		if (argsp->listen_fd + 1 > nfds) nfds = argsp->listen_fd + 1;

		Bag_start_const_iteration(connections);
		for (connections_const_it = Bag_const_begin(connections);
			connections_const_it != Bag_const_end(connections);
			connections_const_it = Bag_const_iterator_next(connections, connections_const_it))
		{
			struct connection_info const * cxn_info = (struct connection_info const *)Bag_const_get(connections, connections_const_it);

			assert(cxn_info != NULL);

			FD_SET(cxn_info->fd);
			if (cxn_info->fd + 1 > nfds) nfds = cxn_info->fd + 1;
		}
		Bag_stop_const_iteration(connections);

		select_retval = select(nfds, &read_fds, NULL, NULL, NULL);

		if (select_retval < 0)
		{
			TODO: log an error
			continue;
		}
		else if (select_retval == 0)
		{
			TODO: log an error
			continue;
		}

		Bag_start_iteration(connections);
		for (did_erase = false; connections_it = Bag_begin(connections);
			connections_it != Bag_end(connections);
			did_erase || connections_it = Bag_next(connections, connections_it))
		{
			struct connection_info * cxn_info = (struct connection_info *)Bag_get(connections, connections_it);

			assert(cxn_info != NULL);

			if (FD_ISSET(cxn_info->fd, &read_fds))
			{
				if (sem_post(cxn_info->semaphore) != 0)
				{
					log an error
					stop the connection thread and free its resources
					free((void *)cxn_info);
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
				log error
				continue;
			}

			cxn_info->semaphore = malloc(sizeof(cxn_semaphore_t));
			if (cxn_info->semaphore == NULL)
			{
				log error
				free((void *)cxn_info);
				continue;
			}

			if (sem_init(cxn_info->semaphore, 0, 0) != 0)
			{
				log error
				free((void *)cxn_info->semphore);
				free((void *)cxn_info);
				continue;
			}

			cxn_info->fd = accept(argsp->listen_fd, NULL, NULL);
			if (cxn_info->fd < 0)
			{
				log error
				if (sem_destroy(cxn_info->semaphore) != 0) log error
				free((void *)cxn_info->semphore);
				free((void *)cxn_info);
				continue;
			}

			struct connection_main_args * connection_args;
			fill in connection_args

			if (pthread_create(&cxn_info->thread, NULL, connection_main, (void *)connection_args) != 0)
			{
				log error
				free((void *)connection_args);
				if (close(cxn_info->fd) != 0) log error
				if (sem_destroy(cxn_info->semaphore) != 0) log error
				free((void *)cxn_info->semphore);
				free((void *)cxn_info);
				continue;
			}

			if (!Bag_add(connections, (void *)cxn_info))
			{
				log error
				cleanup
				continue;
			}

			log new connection
		}
	}
}
