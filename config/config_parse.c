#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "logging.h"

#include "config.h"
#include "config_parse.h"


// special values of enum config_key
#define CONFIG_OPTION_NONE (CONFIG_NUM_ITEMS + 1)
#define CONFIG_OPTION_INCLUDE (CONFIG_NUM_ITEMS + 2)
#define CONFIG_OPTION_UNKNOWN (CONFIG_NUM_ITEMS + 3)


/** Increment the line_offset past all whitespace. */
static void skip_whitespace(const char * line, size_t * line_offset)
{
	*line_offset += strspn(line + *line_offset, CHARS_WHITESPACE);
}

/**
	Increment the line_offset to the end of the line,
	iff line_offset points to the start of a comment.
*/
static void skip_comment(const char * line, size_t * line_offset)
{
	if (strncmp(line + *line_offset, COMMENT_START_STR, strlen(COMMENT_START_STR)) == 0)
	{
		for (; line[*line_offset] != '\0'; ++*line_offset)
		{
			if (line[*line_offset] == '\n')
			{
				return;
			}
		}
	}
}

/**
	Get the option from the beginning of a line.

	@param line_offset	Input/output param for offset within line before/after the option name.
	@param[out] option	Return value of the parsed option, or CONFIG_OPTION_NONE if it's an empty line.
	@return	Whether or not there was an error.
*/
static bool get_option(
	const struct config_option * config_options,
	const struct config_context * context,
	const char * line,
	size_t * line_offset,
	size_t * option)
{
	size_t option_length = strcspn(line + *line_offset, CHARS_WHITESPACE);

	if (option_length == 0)
	{
		config_message(context, LOG_ERROR, "line must start with an option");
		return false;
	}

	if (strspn(line + *line_offset, CHARS_OPTION) != option_length)
	{
		config_message(context, LOG_ERROR, "option name contains an invalid character");
		return false;
	}

	if (strncmp(line + *line_offset, INCLUDE_STR, option_length) &&
		strlen(INCLUDE_STR) == option_length)
	{
		*line_offset += option_length;
		*option = CONFIG_OPTION_INCLUDE;
		return true;
	}

	for (*option = 0; *option < CONFIG_NUM_ITEMS; ++*option)
	{
		if (strncmp(line + *line_offset, config_options[*option].name, option_length) == 0 &&
			strlen(config_options[*option].name) == option_length)
		{
			*line_offset += option_length;
			return true;
		}
	}

	if (ERROR_ON_UNKNOWN_OPTION)
	{
		config_message(context, LOG_ERROR, "unknown option");
		return false;
	}
	else
	{
		config_message(context, LOG_WARNING, "unknown option");
		*line_offset += option_length;
		*option = CONFIG_OPTION_UNKNOWN;
		return true;
	}
}

bool config_parse_file(
	const struct config_option * config_options,
	struct config_value * config_values,
	struct config_context * head,
	struct config_context * tail)
{
	// one line of the file
	char * line = NULL;

	// offset within the line
	size_t line_offset;

	// file being parsed
	FILE * file = NULL;

	// currently "active" option
	size_t option = CONFIG_OPTION_NONE;

	// input values for the currently active option
	char ** values;

	// amount of values array that's currently filled in
	size_t num_values;

	// return value of this function
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

	values = malloc(sizeof(char *) * MAX_ARRAY_LENGTH);
	if (values == NULL)
	{
		LOG(LOG_ERROR, "out of memory");
		ret = false;
		goto done;
	}
	num_values = 0;

	while (fgets(line, MAX_LINE_LENGTH, file) != NULL)
	{
		line_offset = 0;

		if (strlen(line) == MAX_LINE_LENGTH - 1 && line[MAX_LINE_LENGTH - 1] != '\n')
		{
			config_message(head, LOG_ERROR, "line too long");
			ret = false;
			goto done;
		}

		skip_whitespace(line, &line_offset);

		if (option == CONFIG_OPTION_NONE)
		{
			skip_comment(line, &line_offset);

			if (line[line_offset] == '\n')
			{
				// empty line
				continue;
			}
			else if (line[line_offset] == '\0')
			{
				// empty line at end of file
				goto done;
			}

			if (!get_option(config_options, head, line, &line_offset, &option))
			{
				ret = false;
				goto done;
			}
		}

		// TODO
	}

	// if control reaches here, fgets returned NULL
	if (errno != 0)
	{
		tail->line = 0;
		config_message(head, LOG_ERROR, "error reading config file %s: %s",
			tail->file, strerror(errno));
	}

done:

	if (values != NULL)
	{
		for (; num_values != 0; --num_values)
		{
			free(values[num_values - 1]);
		}
		free(values);
		values = NULL;
	}

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
