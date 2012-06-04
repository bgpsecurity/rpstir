#ifndef _CONFIG_PARSE_H
#define _CONFIG_PARSE_H


/**
	Internal header file for parsing a config file.
*/


#include <stdlib.h>
#include <stdbool.h>

#include "config_type.h"


#define MAX_LINE_LENGTH 1024
#define MAX_ARRAY_LENGTH 256

#define CHARS_WHITESPACE " \t" // must not include newline
#define CHARS_OPTION "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

#define INCLUDE_STR "Include"

#define ERROR_ON_UNKNOWN_OPTION false


/** Structure to describe an available config option. */
struct config_option {
	// configuration key, e.g. "SomeOption"
	char * name;

	// type information
	bool is_array;
	config_value_converter value_convert;
	void * value_convert_usr_arg;
	config_value_free value_free;
	config_array_validator array_validate;
	void * array_validate_usr_arg;

	// Default value, as if it came from the config file.
	// NULL indicates that the option is mandatory.
	char * default_value;
};


/**
	Stores the configuration data, which is parsed from the configuration
	file and/or preprogrammed defaults with preference towards the config file.
*/
struct config_value {
	union {
		struct {
			// Filled by the appropriate config_value_converter,
			// freed by the appropriate config_value_free.
			void * data;
		} single_value;

		struct {
			// Each item filled by the appropriate config_value_converter.
			// Overall array checked by the appropriate config_array_validator.
			// Each item freed by the appropriate config_value_free.
			// Overall array freed by free().
			void ** data;
			size_t num_items;
		} array_value;
	};
};


/** Stores context while parsing a configuration file. */
struct config_context {
	const char * file;
	size_t line;

	// pointer to context in included file, or NULL for a line that's not an include line
	struct config_context * includes;
};


/**
	Parses a config file

	@param head	The context for the topmost config file.
	@param tail	The context for the bottommost config file:
			i.e. the one currently being parsed.
*/
bool config_parse_file(
	const struct config_option * config_options,
	struct config_value * config_values,
	struct config_context * head,
	struct config_context * tail);

#endif
