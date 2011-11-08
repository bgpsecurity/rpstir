#include <string.h>

#include "logutils.h"

#include "common.h"

void log_error(int err, char errorbuf[ERROR_BUF_SIZE], char const * prefix)
{
	if (strerror_r(err, errorbuf, ERROR_BUF_SIZE) == 0)
	{
		log_msg(LOG_ERR, "%s: %s", prefix, errorbuf);
	}
	else
	{
		log_msg(LOG_ERR, "%s: error code %d", prefix, err);
	}
}
