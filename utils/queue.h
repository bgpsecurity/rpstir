#ifndef _UTILS_QUEUE_H
#define _UTILS_QUEUE_H


struct _Queue;
typedef struct _Queue Queue;

/** Create a new Queue. */
Queue * Queue_new(bool thread_safe);

/** Free a Queue. Note: the queue must be empty or memory will be leaked. */
void Queue_free(Queue * queue);

/**
	Pop the queue if there's anything on the queue.

	@return Whether or not the pop was successful.
	@param data Returned data if the pop was successful.
*/
bool Queue_trypop(Queue * queue, void ** data);

/**
	Push data onto the queue.

	@return Whether or not the push was successful. (It can fail if there isn't enough memory.)
	@param data The data to put on the queue. This must be a pointer to heap-allocated memory.
*/
bool Queue_push(Queue * queue, void * data);

/** Return the size of the queue */
size_t Queue_size(Queue * queue);


#endif
