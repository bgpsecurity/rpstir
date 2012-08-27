#ifndef _LIB_CONFIG_H
#define _LIB_CONFIG_H

#include <stdlib.h>
#include <stdbool.h>

#include "logging.h"
#include "macros.h"


/** Context in parsing a config file */
struct config_context;


/**
    Callback for config type functions to use to log messages about their config item.

    @param context Opaque data. Might include things like line number in the config file.
    @param priority See syslog(3).
*/
void config_message(
    const struct config_context *context,
    int priority,
    const char *format,
    ...)
    WARN_PRINTF(3, 4);


/**
    Converts a string to a value of the correct type for the config item.

    @note Arrays have this called once for each value.

    @param[in] usr_arg User argument provided to the callback.
    @param[in] input String from the config file. This may be copied,
                     but the pointer itself must not be put in *data.
    @param[out] data A value of the correct type for the config item.
                     May be NULL.
    @return True on success, false on failure. This means that
            this function can be used to validate input.
*/
typedef bool (*config_value_converter) (
    const struct config_context * context,
    void *usr_arg,
    const char *input,
    void **data);

/** Deep free data for a config item. */
typedef void (*config_value_free) (
    void *data);

/** Check an array of values for inter-value consistency/correctness. */
typedef bool (*config_array_validator) (
    const struct config_context * context,
    void *usr_arg,
    void const *const *input,
    size_t num_items);



/** Structure to describe an available config option. */
struct config_option {
    // configuration key, e.g. "SomeOption"
    char *name;

    // type information
    bool is_array;
    config_value_converter value_convert;
    void *value_convert_usr_arg;
    config_value_free value_free;
    config_array_validator array_validate;
    void *array_validate_usr_arg;

    // Default value, as if it came from the config file.
    // NULL indicates that the option is mandatory.
    char *default_value;
};


/** Return the value for a non-array config option. */
const void *config_get(
    size_t key);

/** Return the length of an array config option. */
size_t config_get_length(
    size_t key);

/** Return the values for an array config option. */
void const * const * config_get_array(
    size_t key);

/**
    Load configuration data from a config file.

    @note This is not thread-safe and MUST be called before any threads that
          could possibly use configuration data are started.

    @param num_options Number of config options.
    @param options Description of options.
    @param filename The file to load data from. This can be NULL, see below.
                    It is an error if filename is not NULL and the specified
                    file can't be accessed,
    @param default_filenames NULL-terminated array of (NULL-terminated strings
                             of) files to try if filename is NULL. Each file is
                             tried in order until one exists. Once an existing
                             file is found, no more files are checked. A value
                             of NULL for default_filenames indicates no
                             defaults. If no files are found, it is not
                             inherently an error: the default values for each
                             configuration item are used. However, if there are
                             any mandatory variables, those will cause errors.
*/
bool config_load(
    size_t num_options,
    const struct config_option *options,
    const char *filename,
    char const * const * default_filenames);

/**
    Call this after configuration data is no longer needed to free resources.

    This is usually only called before a program exits.

    @note This MUST NOT be called when any threads could possibly use
          configuration data.
*/
void config_unload(
    );

#endif
