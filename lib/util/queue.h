#ifndef _UTILS_QUEUE_H
#define _UTILS_QUEUE_H


#include <stdbool.h>


struct _Queue;
typedef struct _Queue Queue;

/** Create a new Queue. */
Queue *Queue_new(
    bool thread_safe);

/**
        Free a Queue.

        Notes: The queue must be empty or memory will be leaked.
        Moreover, before calling Queue_free(), the caller must ensure
        that each thread that holds a reference to this Queue has
        completed all operations related to this Queue.
*/
void Queue_free(
    Queue * queue);

/**
	Pop the queue if there's anything on the queue.

	@return Whether or not the pop was successful.
	@param data Returned data if the pop was successful.
*/
bool Queue_trypop(
    Queue * queue,
    void **data);

/**
	Push data onto the queue.

	@return Whether or not the push was successful. (It can fail if there isn't enough memory.)
	@param data The data to put on the queue. This must be a
	            pointer to heap-allocated memory.  The user is
	            responsible for freeing this memory; Queue
	            operations do not dereference or deallocate this
	            pointer.
*/
bool Queue_push(
    Queue * queue,
    void *data);

/**
        Return the approximate size of the queue.  The size returned is
        correct at some point during the time of execution.

        In a multi-threaded environment, size > 0 does not guarantee
        that Queue_trypop() will succeed.  During single-threaded
        operation (i.e. thread_safe = false), Queue_size is fully
        reliable.
*/
size_t Queue_size(
    Queue * queue);


#endif
