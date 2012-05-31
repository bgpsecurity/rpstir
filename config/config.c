#include "config.h"
#include "config_type.h"


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
	// CONFIG_SOME_STRING
	{
		"SomeString",
		false,
		converter_string, NULL,
		free,
		NULL, NULL,
		"\"this is SomeString's the default\""
	},

	// CONFIG_SOME_MANDATORY_STRING
	{
		"SomeMandatoryString",
		false,
		converter_string, NULL,
		free,
		NULL, NULL,
		NULL
	},

	// CONFIG_SOME_UINT16
	{
		"SomeUInt16",
		false,
		converter_sscanf, converter_sscanf_uint16,
		free,
		NULL, NULL,
		"42"
	},

	// CONFIG_SOME_INT64_ARRAY
	{
		"SomeInt64Array",
		true,
		converter_sscanf, converter_sscanf_int64,
		free,
		validate_some_int64_array, NULL,
		"-42 5 56"
	},

	// CONFIG_SOME_STRING_ARRAY
	{
		"SomeStringArray",
		true,
		converter_string, NULL,
		free,
		NULL, NULL,
		"\"string with spaces\" word1 word2 \"another with spaces\""
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

const void ** config_get_array(size_t key)
{
	return config_values[key].array_value.data;
}

bool config_load(const char * filename)
{
	// TODO
}

void config_unload()
{
	// TODO
}
