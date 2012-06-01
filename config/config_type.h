#ifndef _CONFIG_TYPE_H
#define _CONFIG_TYPE_H

#include <stdlib.h>
#include <stdbool.h>

/**
	Internal header file used for defining configuration data types.

	Note that all data types are passed around as (void *) so the
	configuration system itself doesn't need to know anything about
	each type.
*/


/** Context in parsing a config file */
typedef void * config_context_t;

/**
	Callback for config type functions to use to log messages about their config item.

	@param context	Opaque data. Might include things like line number in the config file.
	@param priority	See syslog(3).
*/
void config_mesage(const config_context_t context, int priority, const char * format, ...);


/**
	Converts a string to a value of the correct type for the config item.

	@note Arrays have this called once for each value.

	@param[in] usr_arg	User argument provided to the callback.
	@param[in] input	String from the config file. This may be copied,
				but the pointer itself must not be put in *data.
	@param[out] data	A value of the correct type for the config item.
				May be NULL.
	@return			True on success, false on failure. This means that
				this function can be used to validate input.
*/
typedef bool (*config_value_converter)(const config_context_t context, void * usr_arg, const char * input, void ** data);

/** Deep free data for a config item. */
typedef void (*config_value_free)(void * data);

/** Check an array of values for inter-value consistency/correctness. */
typedef bool (*config_array_validator)(const config_context_t context, void * usr_arg, void const * const * input, size_t num_items);


#endif
