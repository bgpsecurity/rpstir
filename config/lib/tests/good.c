#include "unittest.h"

#include "lib/configlib.h"

#include "lib/types/sscanf.h"
#include "lib/types/string.h"

enum config_key {
	CONFIG_SOME_INT,
	CONFIG_EMPTY_ARRAY,
	CONFIG_STRING_ARRAY,
	CONFIG_INT_ARRAY,
	CONFIG_LONG_ARRAY,
	CONFIG_INCLUDED_INT,
	CONFIG_DEFAULT_STRING,
	CONFIG_DEFAULT_INT_ARRAY,
	CONFIG_DEFAULT_EMPTY_ARRAY,

	CONFIG_NUM_OPTIONS
};


static bool stringarray_validator(
	const struct config_context * context,
	void * usr_arg,
	void const * const * input,
	size_t num_items)
{
	if (usr_arg != (void *)1)
	{
		LOG(LOG_ERR, "usr_arg must be (void *)1");
		return false;
	}

	if (num_items != 3)
	{
		config_message(context, LOG_ERR,
			"must have 3 items, but had %zu",
			num_items);
		return false;
	}

	if (strcmp((const char *)input[0], "foo") != 0)
	{
		config_message(context, LOG_ERR,
			"first element must be \"foo\", but was \"%s\"",
			(const char *)input[0]);
		return false;
	}

	return true;
}


static const struct config_option CONFIG_OPTIONS[] = {
	// CONFIG_SOME_INT
	{
		"SomeInt",
		false,
		config_type_sscanf_converter, config_type_sscanf_arg_int,
		free,
		NULL, NULL,
		NULL
	},

	// CONFIG_EMPTY_ARRAY
	{
		"EmptyArray",
		true,
		config_type_string_converter, NULL,
		free,
		NULL, NULL,
		"foo bar"
	},

	// CONFIG_STRING_ARRAY
	{
		"StringArray",
		true,
		config_type_string_converter, NULL,
		free,
		stringarray_validator, (void*)1,
		"foo 1 3"
	},

	// CONFIG_INT_ARRAY
	{
		"IntArray",
		true,
		config_type_sscanf_converter, config_type_sscanf_arg_int,
		free
		NULL, NULL,
		"1 2 3"
	},

	// CONFIG_LONG_ARRAY
	{
		"LongArray",
		true,
		config_type_string_converter, NULL,
		free,
		NULL, NULL,
		NULL
	},

	// CONFIG_INCLUDED_INT
	{
		"IncludedInt",
		false,
		config_type_sscanf_converter, config_type_sscanf_arg_int,
		free
		NULL, NULL,
		"7"
	},

	// CONFIG_DEFAULT_STRING
	{
		"DefaultString",
		false,
		config_type_string_converter, NULL,
		free,
		NULL, NULL,
		"this-is-the-default"
	},

	// CONFIG_DEFAULT_INT_ARRAY
	{
		"DefaultIntArray",
		true,
		config_type_sscanf_converter, config_type_sscanf_arg_int,
		free,
		NULL, NULL,
		"-1 0 1"
	},

	// CONFIG_DEFAULT_EMPTY_ARRAY,
	{
		"DefaultEmptyArray",
		true,
		config_type_sscanf_converter, config_type_sscanf_arg_int,
		free,
		NULL, NULL,
		""
	},
};
