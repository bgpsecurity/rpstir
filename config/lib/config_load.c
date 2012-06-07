#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>

#include "logging.h"

#include "configlib.h"
#include "config_load.h"


// special values of options
#define CONFIG_OPTION_NONE -1
#define CONFIG_OPTION_INCLUDE -2
#define CONFIG_OPTION_UNKNOWN -3

// start a dynamic array with this many elements
#define DYNAMIC_START 16

// when a dynamic array needs to be expanded, grow it by this factor
#define DYNAMIC_GROW_BY 1.6


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
	size_t num_options,
	const struct config_option * config_options,
	const struct config_context * context,
	const char * line,
	size_t * line_offset,
	ssize_t * option)
{
	size_t option_length = strcspn(line + *line_offset, CHARS_ALL_WHITESPACE);

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

	if (strncmp(line + *line_offset, INCLUDE_STR, option_length) == 0 &&
		strlen(INCLUDE_STR) == option_length)
	{
		*line_offset += option_length;
		*option = CONFIG_OPTION_INCLUDE;
		return true;
	}

	for (*option = 0; (size_t)*option < num_options; ++*option)
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
	@param line_offset	Input/output param for offset within line before/after the option value.
	@param[out] value	Return a malloc()-allocated buffer with the option value.
	@return	True on success, false on error.
*/
static bool get_value(
	const struct config_context * context,
	const char * line,
	size_t * line_offset,
	char ** value)
{
	size_t i;

	// is the value in quotes?
	bool quoted = (line[*line_offset] == '"');

	// does the current character follow a '\\'?
	bool escaped = false;

	// has the value ended normally?
	// (this is used to make sure there's nothing after an ending quote)
	bool done = false;

	bool ret = true;

	// length of variable name
	size_t variable_size;

	// variable name
	char * variable;

	// variable value from environment
	const char * variable_value;

	size_t value_size = 0;
	size_t value_allocated = DYNAMIC_START;

	*value = malloc(value_allocated);
	if (*value == NULL)
	{
		LOG(LOG_ERR, "out of memory");
		ret = false;
		goto done;
	}

	#define ADD_CHAR(c) \
		do { \
			if (value_size >= value_allocated) \
			{ \
				value_allocated *= DYNAMIC_GROW_BY; \
				*value = realloc(*value, value_allocated); \
				if (*value == NULL) \
				{ \
					LOG(LOG_ERR, "out of memory"); \
					ret = false; \
					goto done; \
				} \
			} \
			(*value)[value_size++] = (c); \
		} while (false)

	if (quoted)
	{
		++*line_offset;
	}

	for (; true; ++*line_offset)
	{
		if (done)
		{
			if (line[*line_offset] != '\0' &&
				strchr(CHARS_ALL_WHITESPACE, line[*line_offset]) == NULL)
			{
				config_message(context, LOG_ERR,
					"extraneous character after end of value");
				ret = false;
			}

			goto done;
		}
		else if (quoted && (line[*line_offset] == '\0' || line[*line_offset] == '\n'))
		{
			config_message(context, LOG_ERR,
				"line ended without closing quote");
			ret = false;
			goto done;
		}
		else if (!quoted && (line[*line_offset] == '\0' ||
			strchr(CHARS_ALL_WHITESPACE, line[*line_offset]) != NULL))
		{
			// end of unquoted value
			goto done;
		}
		else if (quoted && !escaped && line[*line_offset] == '"')
		{
			// found end quote
			done = true;
			continue;
		}

		// NOTE: at this point, the current character is either invalid or a continuation
		// of the value. It cannot end the value unless it's invalid.

		if (quoted && !escaped && line[*line_offset] == '\\')
		{
			escaped = true;
			continue;
		}

		if (quoted && escaped)
		{
			if (strchr(CHARS_SPECIAL, line[*line_offset]) != NULL)
			{
				ADD_CHAR(line[*line_offset]);
			}
			else if (line[*line_offset] == 'n')
			{
				ADD_CHAR('\n');
			}
			else if (line[*line_offset] == 'r')
			{
				ADD_CHAR('\r');
			}
			else if (line[*line_offset] == 't')
			{
				ADD_CHAR('\t');
			}
			else
			{
				config_message(context, LOG_ERR,
					"unknown escape sequence \"\\%c\"",
					line[*line_offset]);
				ret = false;
				goto done;
			}

			escaped = false;
			continue;
		}

		if (line[*line_offset] == '$')
		{
			if (line[*line_offset + 1] != '{')
			{
				config_message(context, LOG_ERR,
					"currently, only variable substitution of the form ${FOO} "
					"is supported. The form $FOO is not supported.");
				ret = false;
				goto done;
			}

			variable_size = strcspn(line + *line_offset + 2,
				CHARS_ALL_WHITESPACE CHARS_SPECIAL "}");

			if (line[*line_offset + 2 + variable_size] != '}')
			{
				config_message(context, LOG_ERR,
					"incomplete environment variable. "
					"Variables must end with '}'.");
				ret = false;
				goto done;
			}

			variable = malloc(variable_size + 1);
			if (variable == NULL)
			{
				LOG(LOG_ERR, "out of memory");
				ret = false;
				goto done;
			}

			snprintf(variable, variable_size + 1, "%s", line + *line_offset + 2);

			variable_value = getenv(variable);
			if (variable_value == NULL)
			{
				variable_value = "";
				config_message(context, LOG_WARNING,
					"variable ${%s} not found, using the empty string instead",
					variable);
			}

			free(variable);

			for (i = 0; variable_value[i] != '\0'; ++i)
			{
				ADD_CHAR(variable_value[i]);
			}

			// In addition to the variable name (of length variable_size),
			// there's "${" and "}". The 2 is because after 'continue',
			// *line_offset gets incremented.
			*line_offset += variable_size + 2;
			continue;
		}

		if (strchr(CHARS_SPECIAL, line[*line_offset]) != NULL)
		{
			config_message(context, LOG_ERR,
				"special character (%c) used in an invalid way",
				line[*line_offset]);
			ret = false;
			goto done;
		}

		ADD_CHAR(line[*line_offset]);
	}

done:

	if (ret)
	{
		ADD_CHAR('\0');
	}
	else
	{
		free(*value);
	}

	#undef ADD_CHAR

	return ret;
}

/**
	Get all the values on a line.

	@param head		Context of the line.
	@param tail		Innermost file of the line's context.
	@param option_line	Line where the the option started.
	@param line_offset	Input param for offset within the line before
				the first value to parse. Output param for the
				offset after the inter-word whitespace and
				optional comment after the last value on the
				line. On output, line[*line_offset] should be
				one of: '\n', '\\', or '\0'.
	@param values		Input array of size *num_values (on input),
				allocated to MAX_ARRAY_LENGTH. Output array of
				size *num_values (on output).
	@param num_values	See param values above.
	@return			True on success, false on error.
*/
static bool get_all_values(
	const struct config_context * head,
	struct config_context * tail,
	size_t option_line,
	const char * line,
	size_t * line_offset,
	char ** values,
	size_t * num_values)
{
	size_t line_backup;

	while (true)
	{
		if (strcmp(line + *line_offset, "\\\n") == 0)
		{
			// line continuation
			return true;
		}
		else if (strcmp(line + *line_offset, "\\") == 0)
		{
			config_message(head, LOG_ERR, "line continuation at end of file");
			return false;
		}

		skip_comment(line, line_offset);

		if (line[*line_offset] == '\n')
		{
			// end of line
			return true;
		}
		else if (line[*line_offset] == '\0')
		{
			// end of file
			return true;
		}

		if (*num_values >= MAX_ARRAY_LENGTH)
		{
			line_backup = tail->line;
			tail->line = option_line;
			config_message(head, LOG_ERR, "too many items in an array of values, limit is %d", MAX_ARRAY_LENGTH);
			tail->line = line_backup;
			return false;
		}

		if (get_value(head, line, line_offset, &values[*num_values]))
		{
			++*num_values;
		}
		else
		{
			return false;
		}

		skip_whitespace(line, line_offset);
	}

}

/**
	Convert and validate values from strings to their native types.

	@note config_option and config_value are pointers to individual
		structures, not arrays.

	@param is_default	True if this is being called on values from
				the option's defaults, false if this is being
				called on values from a config file.
*/
static bool convert_values(
	const struct config_context * context,
	const struct config_option * config_option,
	struct config_value * config_value,
	char const * const * values,
	size_t num_values,
	bool is_default)
{
	config_value->filled = true;
	if (!is_default)
	{
		if (config_value->filled_not_default)
		{
			config_message(context, LOG_NOTICE,
				"duplicate option overwriting previous value");
		}

		config_value->filled_not_default = true;
	}

	if (config_option->is_array)
	{
		for (;
			config_value->array_value.num_items != 0;
			--config_value->array_value.num_items)
		{
			config_option->value_free(
				config_value->array_value.data[
					config_value->array_value.num_items - 1]);
		}
		free(config_value->array_value.data);

		config_value->array_value.data = malloc(sizeof(void *) * num_values);
		if (config_value->array_value.data == NULL)
		{
			LOG(LOG_ERR, "out of memory");
			return false;
		}

		for (config_value->array_value.num_items = 0;
			config_value->array_value.num_items < num_values;
			++config_value->array_value.num_items)
		{
			if (!config_option->value_convert(
				context,
				config_option->value_convert_usr_arg,
				values[config_value->array_value.num_items],
				&config_value->array_value.data[
					config_value->array_value.num_items]))
			{
				return false;
			}
		}

		if (config_option->array_validate != NULL)
		{
			if (!config_option->array_validate(
				context,
				config_option->array_validate_usr_arg,
				(void const * const *)config_value->array_value.data,
				config_value->array_value.num_items))
			{
				return false;
			}
		}
	}
	else
	{
		if (num_values != 1)
		{
			config_message(context, LOG_ERR,
				"non-array option must have exactly one value");
			return false;
		}

		config_option->value_free(config_value->single_value.data);
		config_value->single_value.data = NULL;

		if (!config_option->value_convert(
			context,
			config_option->value_convert_usr_arg,
			values[0],
			&config_value->single_value.data))
		{
			return false;
		}
	}

	return true;
}

bool config_parse_file(
	size_t num_options,
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
	ssize_t option = CONFIG_OPTION_NONE;

	// line number where currently active option started
	size_t option_line;

	// backup line number
	size_t line_backup;

	// input values for the currently active option
	char ** values = NULL;

	// amount of values array that's currently filled in
	size_t num_values;

	// for changing directories and going back
	char * oldpwd = NULL;
	char * filename_dirname = NULL; // copy of file name for dirname(3)
	char * newpwd;

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

	oldpwd = malloc(PATH_MAX);
	if (oldpwd == NULL)
	{
		LOG(LOG_ERR, "out of memory");
		ret = false;
		goto done;
	}
	if (getcwd(oldpwd, PATH_MAX) == NULL)
	{
		LOG(LOG_ERR, "getcwd(): %s", strerror(errno));
		free(oldpwd);
		oldpwd = NULL;
		ret = false;
		goto done;
	}

	filename_dirname = strdup(tail->file);
	if (filename_dirname == NULL)
	{
		LOG(LOG_ERR, "out of memory");
		ret = false;
		goto done;
	}
	newpwd = dirname(filename_dirname);

	if (chdir(newpwd) != 0)
	{
		LOG(LOG_ERR, "chdir(%s): %s", newpwd, strerror(errno));
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

			if (!get_option(num_options,
				config_options,
				head,
				line,
				&line_offset,
				&option))
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
		}

		if (!get_all_values(head, tail, option_line, line, &line_offset, values, &num_values))
		{
			ret = false;
			goto done;
		}

		if (strcmp(line + line_offset, "\\\n") == 0)
		{
			// line continuation
			continue;
		}

		if (option == CONFIG_OPTION_INCLUDE)
		{
			if (num_values != 1)
			{
				tail->line = option_line;
				config_message(head, LOG_ERR, "include should take exactly one file");
				ret = false;
				goto done;
			}

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

			line_backup = tail->line;
			tail->line = option_line;
			ret = config_parse_file(num_options,
				config_options,
				config_values,
				head,
				tail->includes);
			tail->line = line_backup;

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
		else
		{
			line_backup = tail->line;
			tail->line = option_line;
			ret = convert_values(head,
				&config_options[option],
				&config_values[option],
				(char const * const *)values,
				num_values,
				false);
			tail->line = line_backup;
			if (!ret)
			{
				goto done;
			}
		}

		option = CONFIG_OPTION_NONE;

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

	newpwd = NULL;
	free(filename_dirname);
	filename_dirname = NULL;

	if (oldpwd != NULL)
	{
		if (chdir(oldpwd) != 0)
		{
			LOG(LOG_ERR, "chdir(%s): %s", oldpwd, strerror(errno));
			ret = false;
		}

		free(oldpwd);
		oldpwd = NULL;
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


bool config_load_defaults(
	size_t num_options,
	const struct config_option * config_options,
	struct config_value * config_values,
	struct config_context * context)
{
	bool ret = true;
	size_t option;
	size_t line_offset;
	char * values[MAX_ARRAY_LENGTH];
	size_t num_values = 0;

	// initialize config_values
	for (option = 0; option < num_options; ++option)
	{
		config_values[option].filled = false;
		config_values[option].filled_not_default = false;
		if (config_options[option].is_array)
		{
			config_values[option].array_value.data = NULL;
			config_values[option].array_value.num_items = 0;
		}
		else
		{
			config_values[option].single_value.data = NULL;
		}
	}

	// parse defaults
	for (option = 0; option < num_options; ++option)
	{
		if (config_options[option].default_value == NULL)
		{
			continue;
		}

		line_offset = 0;

		for (; num_values != 0; --num_values)
		{
			free(values[num_values - 1]);
		}

		if (!get_all_values(context,
			context,
			0,
			config_options[option].default_value,
			&line_offset,
			values,
			&num_values))
		{
			config_message(context, LOG_ERR, "%s has invalid default value",
				config_options[option].name);
			ret = false;
			goto done;
		}

		if (config_options[option].default_value[line_offset] != '\0')
		{
			config_message(context, LOG_ERR,
				"%s's default values should only use one line",
				config_options[option].name);
			ret = false;
			goto done;
		}

		if (!convert_values(context,
			&config_options[option],
			&config_values[option],
			(char const * const *)values,
			num_values,
			true))
		{
			config_message(context, LOG_ERR, "error parsing %s's default value",
				config_options[option].name);
			ret = false;
			goto done;
		}
	}

done:

	for (; num_values != 0; --num_values)
	{
		free(values[num_values - 1]);
	}

	return ret;
}
