#include "config.h"
#include "config_type.h"

#include "types/string.h"


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


/** All available config options */
static const struct config_option config_options[] = {
	// CONFIG_ROOT
	{
		"Root",
		false,
		converter_string, NULL,
		free,
		NULL, NULL,
		ABS_TOP_SRCDIR
	},
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
			const void * data;
		} single_value;

		struct {
			// Each item filled by the appropriate config_value_converter.
			// Overall array checked by the appropriate config_array_validator.
			// Each item freed by the appropriate config_value_free.
			// Overall array freed by free().
			const void ** data;
			size_t num_items;
		} array_value;
	}
};


/** Stores all config data. */
static struct config_value config_values[CONFIG_NUM_ITEMS];


const void * config_get(size_t key)
{
	return config_values[key].single_value.data;
}

size_t config_get_length(size_t key)
{
	return config_values[key].array_value.num_items;
}

void const * const * config_get_array(size_t key)
{
	return config_values[key].array_value.data;
}


struct config_context {
	char * file;
	size_t line;
};

void config_mesage(const config_context_t context_voidp, int priority, const char * format, ...)
{
	struct config_context * context = (struct config_context *)context_voidp;
	// TODO
}

bool config_load(const char * filename)
{
	// TODO
}

void config_unload()
{
	// TODO
}
