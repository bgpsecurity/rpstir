#include <stdlib.h>

#include "logging.h"

#include "cache_state.h"

static bool get_cache_state(struct cache_state * state /* TODO: DB connection */)
{
	if (state == NULL)
	{
		LOG(LOG_ERR, "get_cache_state() got NULL state");
		return false;
	}

	// TODO: real implementation instead of this stub

	state->nonce = 0;
	state->serial_number = rand();

	return true;
}

bool initialize_global_cache_state(struct global_cache_state * state)
{
	if (state == NULL)
	{
		LOG(LOG_ERR, "initialize_global_cache_state got NULL state");
		return false;
	}

	// TODO: DB connection

	bool ret = get_cache_state(&state->cache_state);

	int retval = pthread_rwlock_init(&state->lock, NULL);
	if (retval != 0)
	{
		char errorbuf[ERROR_BUF_SIZE];
		ERR_LOG(retval, errorbuf, "pthread_rwlock_init() for global cache state");
		return false;
	}

	return ret;
}

bool update_global_cache_state(struct global_cache_state * state)
{
	if (state == NULL)
	{
		LOG(LOG_ERR, "update_global_cache_state got NULL state");
		return false;
	}

	bool ret;
	int retval;
	char errorbuf[ERROR_BUF_SIZE];

	retval = pthread_rwlock_wrlock(&state->lock);
	if (retval != 0)
	{
		ERR_LOG(retval, errorbuf, "pthread_rwlock_wrlock() for global cache state");
		return false;
	}

	struct cache_state tmp_cache_state;
	ret = get_cache_state(&tmp_cache_state);
	if (ret)
	{
		state->cache_state = tmp_cache_state;
	}
	else
	{
		LOG(LOG_WARNING, "couldn't update global cache state, leaving cache state unchanged");
	}

	retval = pthread_rwlock_unlock(&state->lock);
	if (retval != 0)
	{
		ERR_LOG(retval, errorbuf, "pthread_rwlock_unlock() for global cache state");
		return false;
	}

	return ret;
}

void close_global_cache_state(struct global_cache_state * state)
{
	if (state == NULL)
	{
		LOG(LOG_ERR, "close_global_cache_state got NULL state");
		return;
	}

	int retval;
	char errorbuf[ERROR_BUF_SIZE];

	retval = pthread_rwlock_destroy(&state->lock);
	if (retval != 0)
	{
		ERR_LOG(retval, errorbuf, "pthread_rwlock_destroy() for global cache state");
	}

	// TODO: DB connection
}
