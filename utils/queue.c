#include <pthread.h>
#include <stdlib.h>

#include "queue.h"


#ifdef DEBUG
#include <assert.h>
#define QUEUE_INVARIANTS(queue) \
		do { \
			if (queue != NULL) { \
				assert(queue->size >= 0); \
				if (queue->size == 0) { \
					assert(queue->first == NULL); \
					assert(queue->last == NULL); \
				} else { \
					assert(queue->first != NULL); \
					assert(queue->last != NULL); \
					assert(queue->first->prev == NULL); \
					assert(queue->last->next == NULL); \
				} \
			} \
		} while (false)
         // Should we also assert that e->next->prev == e and
         // e->prev->next == e for all relevant entries?
#else
#define assert(x) \
		do { \
		} while (false)
#define QUEUE_INVARIANTS(queue) \
		do { \
		} while (false)
#endif


struct _Queue_Entry {
    struct _Queue_Entry *prev;
    struct _Queue_Entry *next;
    void *data;
};

struct _Queue {
    bool thread_safe;           // NOTE: this must not be changed once
                                // Queue_new returns
    pthread_mutex_t mutex;

#ifdef DEBUG
    ssize_t size;               // helps make sure size is never decremented
                                // from 0
#else
    size_t size;
#endif

    struct _Queue_Entry *first;
    struct _Queue_Entry *last;
};


Queue *Queue_new(
    bool thread_safe)
{
    Queue *queue = (Queue *) malloc(sizeof(Queue));
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

    QUEUE_INVARIANTS(queue);

    return queue;
}

void Queue_free(
    Queue * queue)
{
    QUEUE_INVARIANTS(queue);

    if (queue == NULL)
        return;

    /*
     * N.B. The following check is necessary but not sufficient for safety.
     * The caller is responsible for ensuring that all threads are finished
     * with this queue. 
     */
    assert(queue->size == 0);

    if (queue->thread_safe)
        pthread_mutex_destroy(&queue->mutex);

    free((void *)queue);
}

static inline bool Queue_lock(
    Queue * queue)
{
    assert(queue != NULL);

    if (queue->thread_safe)
        if (pthread_mutex_lock(&queue->mutex) != 0)
            return false;

    QUEUE_INVARIANTS(queue);

    return true;
}

static inline bool Queue_unlock(
    Queue * queue)
{
    assert(queue != NULL);

    QUEUE_INVARIANTS(queue);

    if (queue->thread_safe)
        if (pthread_mutex_unlock(&queue->mutex) != 0)
            return false;

    return true;
}

bool Queue_trypop(
    Queue * queue,
    void **data)
{
    struct _Queue_Entry *entry;

    assert(queue != NULL);

    if (!Queue_lock(queue))
        return false;

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

        // ignore the return value because there's nothing good to do with it
        // anyway
        Queue_unlock(queue);

        *data = entry->data;

        free((void *)entry);

        return true;
    }
}

bool Queue_push(
    Queue * queue,
    void *data)
{
    struct _Queue_Entry *entry;

    assert(queue != NULL);

    entry = (struct _Queue_Entry *)malloc(sizeof(struct _Queue_Entry));
    if (entry == NULL)
        return false;

    entry->next = NULL;
    entry->data = data;

    if (!Queue_lock(queue))
    {
        free(entry);
        return false;
    }

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

    return Queue_unlock(queue);
}

size_t Queue_size(
    Queue * queue)
{
    size_t size;

    assert(queue != NULL);

    // The return values of lock() and unlock() are ignored because
    // I couldn't think of a good way to handle them without introducing
    // significant extra amounts of code, and Queue_size()
    // isn't as important as the other functions anyway.

    Queue_lock(queue);

    size = queue->size;

    Queue_unlock(queue);

    return size;
}
