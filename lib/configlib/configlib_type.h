#ifndef _LIB_CONFIGLIB_CONFIGLIB_TYPE_H
#define _LIB_CONFIGLIB_CONFIGLIB_TYPE_H

/**
    This file contains the declarations necessary to define new configuration
    types, e.g. string, tcp/udp port number, or filesystem path. It is included
    by configlib.h, so it doesn't need to be explicitly included.

    To see example type implementations, see the types directory.
*/


/**
    Context in parsing a config file. This should be opaque to implementations
    of config types.
*/
struct config_context;


/**
    @return True iff the context is for a default value, as opposed to a value
            from a configuration file.
*/
bool config_context_is_default(
    const struct config_context * context);


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
                     It can be NULL if the config file has no value for
                     a non-array option.
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

/**
    Converts the result of a config_value_converter back to a string.

    @return a malloc() allocated string, or NULL on error
*/
typedef char * (*config_value_converter_inverse) (
    void *usr_arg,
    void *input);

/** Deep free data for a config item. */
typedef void (*config_value_free) (
    void *data);

/** Check an array of values for inter-value consistency/correctness. */
typedef bool (*config_array_validator) (
    const struct config_context * context,
    void *usr_arg,
    void const *const *input,
    size_t num_items);


#endif
