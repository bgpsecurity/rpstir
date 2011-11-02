#include <pthread.h>

#include "queue.h"


struct _Queue_Entry {
	struct _Queue_Entry * prev;
	struct _Queue_Entry * next;
	void * const data;
};

struct _Queue {
	bool thread_safe; // NOTE: this must not be changed once Queue_new returns
	pthread_mutex_t mutex;
	size_t size;
	struct _Queue_Entry * first;
	struct _Queue_Entry * last;
};


Queue * Queue_new(bool thread_safe)
{
	Queue * queue = (Queue *)malloc(sizeof(Queue));
	if (queue == NULL)
		return NULL;

	queue->thread_safe = thread_safe;

	if (queue->thread_safe)
	{
		if (pthread_mutex_init(&queue->mutex, NULL) != 0)
		{
			free((void *)queue);
			return NULL;
		}
	}

	queue->size = 0;
	queue->first = NULL;
	queue->last = NULL;
}

void Queue_free(Queue * queue)
{
	if (queue == NULL)
		return;

	if (queue->thread_safe)
		pthread_mutex_destroy(&queue->mutex);

	free((void *)queue);
}

static inline void Queue_lock(Queue * queue)
{
	if (queue->thread_safe)
		pthread_mutex_lock(&queue->mutex);
}

static inline void Queue_unlock(Queue * queue)
{
	if (queue->thread_safe)
		pthread_mutex_unlock(&queue->mutex);
}

bool Queue_trypop(Queue * queue, void ** data)
{
	struct _Queue_Entry * entry;

	Queue_lock(queue);

	entry = queue->first;

	if (entry == NULL)
	{
		Queue_unlock(queue);
		return false;
	}
	else
	{
		// remove entry from the queue
		queue->first = entry->next;
		if (queue->first == NULL)
		{
			queue->last = NULL;
		}
		else
		{
			queue->first->prev = NULL;
		}
		queue->size -= 1;

		Queue_unlock(queue);

		*data = entry->data;

		free((void *)entry)

		return true;
	}
}

bool Queue_push(Queue * queue, void * data)
{
	struct _Queue_Entry * entry;

	entry = (struct _Queue_Entry *)malloc(sizeof(struct _Queue_Entry));
	if (entry == NULL)
		return false;

	entry->next = NULL;
	entry->data = data;

	Queue_lock(queue);

	entry->prev = queue->last;
	if (queue->last == NULL)
	{
		queue->first = entry;
	}
	else
	{
		queue->last->next = entry;
	}
	queue->last = entry;
	queue->size += 1;

	Queue_unlock(queue);

	return true;
}

size_t Queue_size(Queue * queue)
{
	size_t size;

	Queue_lock(queue);

	size = queue->size;

	Queue_unlock(queue);

	return size;
}
