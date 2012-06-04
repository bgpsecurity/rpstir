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
	@return	True on success, false on error.
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
		config_message(context, LOG_ERR, "line must start with an option");
		return false;
	}

	if (strspn(line + *line_offset, CHARS_OPTION) != option_length)
	{
		config_message(context, LOG_ERR, "option name contains an invalid character");
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
		config_message(context, LOG_ERR, "unknown option");
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

/**
	Get the next value to an option.

	@param line		The line itself.
	@param line_offset	Input/output param for offset within line before/after the option name.
	@param[out] value	Return a malloc()-allocated buffer with the option value.
	@return	True on success, false on error.
*/
static bool get_value(
	const struct config_context * context,
	const char * line,
	size_t * line_offset,
	char ** value)
{
	// TODO: real implementation with quoting, escape sequences, and environment variables
	size_t value_length = strcspn(line + *line_offset, CHARS_WHITESPACE);

	*value = strndup(line + *line_offset, value_length);

	if (*value == NULL)
	{
		LOG(LOG_ERR, "out of memory");
		return false;
	}

	*line_offset += value_length;
	return true;
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

	// line number where currently active option started
	size_t option_line;

	// input values for the currently active option
	char ** values;

	// amount of values array that's currently filled in
	size_t num_values;

	// whether or not an array is expected
	bool is_array;

	// return value of this function
	bool ret = true;

	line = malloc(MAX_LINE_LENGTH);
	if (line == NULL)
	{
		LOG(LOG_ERR, "out of memory");
		ret = false;
		goto done;
	}

	file = fopen(tail->file, "r");
	if (file == NULL)
	{
		config_message(head, LOG_ERR, "cannot open config file %s: %s",
			tail->file, strerror(errno));
		ret = false;
		goto done;
	}

	values = malloc(sizeof(char *) * MAX_ARRAY_LENGTH);
	if (values == NULL)
	{
		LOG(LOG_ERR, "out of memory");
		ret = false;
		goto done;
	}
	num_values = 0;

	while (fgets(line, MAX_LINE_LENGTH, file) != NULL)
	{
		++tail->line;
		line_offset = 0;

		if (strlen(line) == MAX_LINE_LENGTH - 1 && line[MAX_LINE_LENGTH - 1] != '\n')
		{
			config_message(head, LOG_ERR, "line too long");
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

			skip_whitespace(line, &line_offset);

			option_line = tail->line;

			for (; num_values != 0; --num_values)
			{
				free(values[num_values - 1]);
			}

			if (option == CONFIG_OPTION_INCLUDE)
			{
				is_array = false;
			}
			else if (option == CONFIG_OPTION_UNKNOWN)
			{
				is_array = true;
			}
			else
			{
				is_array = config_options[option].is_array;
			}
		}

		while (true)
		{
			if (strcmp(line + line_offset, "\\\n") == 0)
			{
				// line continuation
				break;
			}
			else if (strcmp(line + line_offset, "\\") == 0)
			{
				config_message(head, LOG_ERR, "line continuation at end of file");
				ret = false;
				goto done;
			}

			skip_comment(line, &line_offset);

			if (line[line_offset] == '\n')
			{
				// end of line
				break;
			}
			else if (line[line_offset] == '\0')
			{
				// end of file
				break;
			}

			if (num_values >= MAX_ARRAY_LENGTH)
			{
				tail->line = option_line;
				config_message(head, LOG_ERR, "too many items in an array of values, limit is %d", MAX_ARRAY_LENGTH);
				ret = false;
				goto done;
			}

			if (!get_value(head, line, &line_offset, &values[num_values++]))
			{
				ret = false;
				goto done;
			}
		}

		if (strcmp(line + line_offset, "\\\n") == 0)
		{
			// line continuation
			continue;
		}

		if (!is_array && num_values != 1)
		{
			tail->line = option_line;
			config_message(head, LOG_ERR, "non-array option must have exactly one value");
			ret = false
			goto done;
		}

		if (option == CONFIG_OPTION_INCLUDE)
		{
			tail->includes = malloc(sizeof(struct config_context));
			if (tail->includes == NULL)
			{
				LOG(LOG_ERR, "out of memory");
				ret = false;
				goto done;
			}

			tail->includes->file = values[0];
			tail->includes->line = 0;
			tail->includes->includes = NULL;

			ret = config_parse_file(config_options, config_values, head, tail->includes);

			free(tail->includes);
			tail->includes = NULL;

			if (!ret)
			{
				goto done;
			}
		}
		else if (option == CONFIG_OPTION_UNKNOWN)
		{
			// nothing to do here
		}
		else if (is_array)
		{
			for (;
				config_values[option].array_value.num_items != 0;
				--config_values[option].array_value.num_items)
			{
				config_options[option].value_free(
					config_values[option].array_value.data[
						config_values[option].array_value.num_items - 1]);
			}
			free(config_values[option].array_value.data);

			config_values[option].array_value.data = malloc(sizeof(void *) * num_values);
			if (config_values[option].array_value.data == NULL)
			{
				LOG(LOG_ERR, "out of memory");
				ret = false;
				goto done;
			}

			for (config_values[option].array_value.num_items = 0;
				config_values[option].array_value.num_items < num_values;
				++config_values[option].array_value.num_items)
			{
				if (!config_options[option].value_convert(
					head,
					config_options[option].value_convert_usr_arg,
					values[config_values[option].array_value.num_items],
					&config_values[option].array_value.data[
						config_values[option].array_value.num_items]))
				{
					ret = false;
					goto done;
				}
			}

			if (!config_options[option].array_validate(
				head,
				config_options[option].array_validate_usr_arg,
				config_values[option].array_value.data,
				config_values[option].array_value.num_items))
			{
				ret = false;
				goto done;
			}
		}
		else
		{
			config_options[option].value_free(config_values[option].single_value.data);
			config_values[option].single_value.data = NULL;

			if (!config_options[option].value_convert(
				head,
				config_options[option].value_convert_usr_arg,
				values[0],
				&config_values[option].single_value.data))
			{
				ret = false;
				goto done;
			}
		}

		if (line[line_offset] == '\0')
		{
			// end of file
			goto done;
		}
	}

	// if control reaches here, fgets returned NULL
	if (errno != 0)
	{
		tail->line = 0;
		config_message(head, LOG_ERR, "error reading config file %s: %s",
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
			config_message(head, LOG_ERR, "cannot close config file %s: %s",
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
