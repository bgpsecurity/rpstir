#include <stdlib.h>

#include "logging.h"
#include "mysql-c-api/connect.h"
#include "mysql-c-api/rtr.h"

#include "cache_state.h"

// NOTE: if this returns false, the contents of state are undefined
static bool get_cache_state(struct cache_state * state, void * db)
{
	if (state == NULL)
	{
		LOG(LOG_ERR, "get_cache_state() got NULL state");
		return false;
	}

	if (getCacheNonce(db, &state->nonce) != 0)
	{
		LOG(LOG_WARNING, "error getting cache nonce");
		return false;
	}

	switch (getLatestSerialNumber(db, &state->serial_number))
	{
		case GET_SERNUM_SUCCESS:
			state->data_available = true;
			break;
		case GET_SERNUM_NONE:
			state->data_available = false;
			break;
		default:
			LOG(LOG_ERR, "error getting latest serial number");
			return false;
	}

	return true;
}

bool initialize_global_cache_state(struct global_cache_state * state, void * db)
{
	if (state == NULL)
	{
		LOG(LOG_ERR, "initialize_global_cache_state got NULL state");
		return false;
	}

	if (!get_cache_state(&state->cache_state, db))
		return false;

	if (!state->cache_state.data_available)
		LOG(LOG_NOTICE, "no cache data available");

	int retval = pthread_rwlock_init(&state->lock, NULL);
	if (retval != 0)
	{
		char errorbuf[ERROR_BUF_SIZE];
		ERR_LOG(retval, errorbuf, "pthread_rwlock_init() for global cache state");
		return false;
	}

	return true;
}

bool update_global_cache_state(struct global_cache_state * state, void * db)
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
	ret = get_cache_state(&tmp_cache_state, db);
	if (ret)
	{
		if (tmp_cache_state.data_available && !state->cache_state.data_available)
		{
			LOG(LOG_NOTICE, "cache data became available");
		}
		else if (!tmp_cache_state.data_available && state->cache_state.data_available)
		{
			LOG(LOG_WARNING, "cache data became no longer available");
		}

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
}
