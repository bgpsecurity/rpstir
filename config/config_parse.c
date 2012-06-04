#include <stdio.h>
#include <string.h>

#include "logging.h"

#include "config.h"
#include "config_parse.h"


bool config_parse_file(
	const struct config_option * config_options,
	struct config_value * config_values,
	struct config_context * head,
	struct config_context * tail)
{
	char * line = NULL;
	FILE * file = NULL;
	bool ret = true;

	line = malloc(MAX_LINE_LENGTH);
	if (line == NULL)
	{
		LOG(LOG_ERROR, "out of memory");
		ret = false;
		goto done;
	}

	file = fopen(tail->file, "r");
	if (file == NULL)
	{
		config_message(head, LOG_ERROR, "cannot open config file %s: %s",
			tail->file, strerror(errno));
		ret = false;
		goto done;
	}

	// TODO: parse the file

done:

	if (file != NULL)
	{
		if (fclose(file) != 0)
		{
			config_message(head, LOG_ERROR, "cannot close config file %s: %s",
				tail->file, strerror(errno));
		}
		file = NULL;
	}

	if (line != NULL)
	{
		free(line);
		line = NULL;
	}

	return ret;
}
