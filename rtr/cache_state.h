#ifndef _RTR_CACHE_STATE_H
#define _RTR_CACHE_STATE_H

#include <pthread.h>
#include <stdbool.h>

#include "pdu.h"

struct cache_state {
	cache_nonce_t nonce;
	serial_number_t serial_number;
};

struct global_cache_state {
	struct cache_state cache_state;
	// TODO: DB connection
	pthread_rwlock_t lock;
};

/**
	\brief Initialize the global cache state.

	Initialize the lock and get the nonce and serial number from the database.

	@return Whether or not the initialization was successful.
*/
bool initialize_global_cache_state(struct global_cache_state * state);

/**
	Update the global cache state from the database.

	@return Whether or not the update was successful.
*/
bool update_global_cache_state(struct global_cache_state * state);

/** Free up any resources associated with the global cache state. */
void close_global_cache_state(struct global_cache_state * state);

#endif
