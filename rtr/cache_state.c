#include <stdlib.h>

#include "logging.h"
#include "mysql-c-api/rtr.h"

#include "cache_state.h"

// NOTE: if this returns false, the contents of state are undefined
static bool get_cache_state(struct cache_state * state, dbconn * db)
{
	if (state == NULL)
	{
		LOG(LOG_ERR, "get_cache_state() got NULL state");
		return false;
	}

	if (db_rtr_get_session_id(db, &state->session) != 0)
	{
		LOG(LOG_WARNING, "error getting session id");
		return false;
	}

	switch (db_rtr_get_latest_sernum(db, &state->serial_number))
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

bool initialize_global_cache_state(struct global_cache_state * state, dbconn * db)
{
	if (state == NULL)
	{
		LOG(LOG_ERR, "initialize_global_cache_state got NULL state");
		return false;
	}

	if (!get_cache_state(&state->cache_state, db))
		return false;

	if (state->cache_state.data_available)
	{
		LOG(LOG_INFO, "cache data initialized with session %" PRISESSION " and serial number %" PRISERIAL,
			state->cache_state.session,
			state->cache_state.serial_number);
	}
	else
	{
		LOG(LOG_NOTICE, "no cache data available (session = %" PRISESSION ")",
			state->cache_state.session);
	}

	int retval = pthread_rwlock_init(&state->lock, NULL);
	if (retval != 0)
	{
		char errorbuf[ERROR_BUF_SIZE];
		ERR_LOG(retval, errorbuf, "pthread_rwlock_init() for global cache state");
		return false;
	}

	return true;
}

bool update_global_cache_state(struct global_cache_state * state, dbconn * db)
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
			LOG(LOG_NOTICE, "cache data became available (session = %" PRISESSION ", serial = %" PRISERIAL ")",
				tmp_cache_state.session,
				tmp_cache_state.serial_number);
		}
		else if (!tmp_cache_state.data_available && state->cache_state.data_available)
		{
			LOG(LOG_WARNING, "cache data became no longer available (old session = %" PRISESSION ", old serial = %" PRISERIAL ")",
				state->cache_state.session,
				state->cache_state.serial_number);
		}
		else if (tmp_cache_state.data_available &&
			state->cache_state.data_available &&
			tmp_cache_state.serial_number != state->cache_state.serial_number)
		{
			LOG(LOG_INFO, "cache serial number changed from %" PRISERIAL " to %" PRISERIAL,
				state->cache_state.serial_number,
				tmp_cache_state.serial_number);
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
