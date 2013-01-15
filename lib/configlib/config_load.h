#ifndef _LIB_CONFIGLIB_CONFIG_LOAD_H
#define _LIB_CONFIGLIB_CONFIG_LOAD_H


/**
	Internal header file for loading a config.
*/


#include <stdlib.h>
#include <stdbool.h>

#include "configlib.h"


#define MAX_LINE_LENGTH 2048
#define MAX_ARRAY_LENGTH 256

#define CHARS_WHITESPACE " \t"  // must not include newline
#define CHARS_ALL_WHITESPACE CHARS_WHITESPACE "\n"
#define CHARS_OPTION "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define CHARS_SPECIAL "\"$\\"

#define INCLUDE_STR "Include"
#define COMMENT_START_STR "#"

#define ERROR_ON_UNKNOWN_OPTION false


/**
	Stores the configuration data, which is parsed from the configuration
	file and/or preprogrammed defaults with preference towards the config file.
*/
struct config_value {
    bool filled;
    bool filled_not_default;    // filled by a config file (as opposed to a
                                // default in C)

    union {
        struct {
            // Filled by the appropriate config_value_converter,
            // freed by the appropriate config_value_free.
            void *data;
        } single_value;

        struct {
            // Each item filled by the appropriate config_value_converter.
            // Overall array checked by the appropriate
            // config_array_validator.
            // Each item freed by the appropriate config_value_free.
            // Overall array freed by free().
            void **data;
            size_t num_items;
        } array_value;
    } value;
};


/** Stores context while parsing a configuration file. */
struct config_context {
    // whether this is from a default (in C) or from a file
    bool is_default;

    union {
        struct config_context_default {
            const char *option;
        } default_context;

        struct config_context_file {
            const char *file;
            size_t line;

            // pointer to context in included file, or NULL for a line that's
            // not an include line
            struct config_context_file *includes;
        } file_context;
    } context;
};


/**
	Parses a config file

	@param head	The context for the topmost config file.
	@param tail	The context for the bottommost config file:
			i.e. the one currently being parsed.
*/
bool config_parse_file(
    size_t num_options,
    const struct config_option *config_options,
    struct config_value *config_values,
    struct config_context *head,
    struct config_context_file *tail);

/**
	Loads defaults and initializes config_values.
*/
bool config_load_defaults(
    size_t num_options,
    const struct config_option *config_options,
    struct config_value *config_values);

#endif
