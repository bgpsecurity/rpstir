// PUBLIC HEADER FILE
enum config_key {
	CONFIG_SOME_STRING,
	CONFIG_SOME_MANDATORY_STRING,
	CONFIG_SOME_UINT16,
	CONFIG_SOME_INT64_ARRAY,
	CONFIG_SOME_STRING_ARRAY,

	CONFIG_NUM_ITEMS
};

/** Return the value for a non-array config option. */
const void * config_get(size_t key);

/** Return the length of an array config option. */
size_t config_get_length(size_t key);

/** Return the values for an array config option. */
const void ** config_get_array(size_t key);

// TODO: config_load() and config_unload()

// PRIVATE HEADER FILE

/**
	Stores the configuration data, which is parsed from the configuration
	file and preprogrammed defaults with preference towards the config file.
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

/**
	Converts a string to a value of the correct type for the config item.

	@note Arrays have this called once for each value.

	@param[in] usr_arg	User argument provided to the callback.
	@param[in] input	String from the config file.
	@param[out] output	A value of the correct type for the config item.
				May be NULL.
	@return			True on success, false on failure. This means that
				this function can be used to validate input.
*/
typedef bool (*config_value_converter)(void * usr_arg, const char * input, const void ** output);

/** Deep free data for a config item. */
typedef void (*config_value_free)(const void * data);

/** Check an array of values for inter-value consistency/correctness. */
typedef bool (*config_array_validator)(void * usr_arg, const void ** input, size_t num_items);

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

// C file

struct converter_sscanf_usr_arg {
	char * scan_format; // e.g. SCNu16. note that this does not include the '%' character
	size_t allocate_length;
}
static bool converter_sscanf(void * usr_arg, const char * input, const void ** output)
{
	struct converter_sscanf_usr_arg * args = (struct converter_sscanf_usr_arg *)usr_arg;
	char scan_format[32];
	int consumed;

	*output = malloc(args->allocate_length);
	if (*output == NULL)
	{
		LOG(LOG_ERR, "out of memory");
		return false;
	}

	if (snprintf(scan_format, sizeof(scan_format), "%%%s%%n", args->scan_format) >= sizeof(scan_format))
	{
		LOG(LOG_ERR, "scan_format too long: %s", args->scan_format);
		free(*output);
		return false;
	}

	if (sscanf(input, scan_format, *output, &consumed) < 1 ||
		consumed < strlen(input))
	{
		LOG(LOG_ERR, "Invalid value: %s", input);
		free(*output);
		return false;
	}

	return true;
}

static bool converter_string(void * usr_arg, const char * input, const void ** output)
{
	*output = strdup(input);
	if (*output == NULL)
	{
		LOG(LOG_ERR, "out of memory");
		return false;
	}

	return true;
}

static const struct converter_sscanf_uint16 = {SCNu16, sizeof(uint16_t)};
static const struct converter_sscanf_int64 = {SCNi64, sizeof(int64_t)};

static bool validate_some_int64_array(void * usr_arg, const void ** input, size_t num_items)
{
	if (num_items < 2)
	{
		LOG(LOG_ERR, "SomeInt64Array must have at least 2 items");
		return false;
	}

	if (*(int64_t *)(input[0]) >= 0)
	{
		LOG(LOG_ERR, "The first item in SomeInt64Array must be negative");
		return false;
	}

	return true;
}

static const struct config_option config_options[] = {
	// CONFIG_SOME_STRING
	{
		"SomeString",
		false,
		converter_string, NULL,
		free,
		NULL, NULL,
		"this is SomeString's the default"
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
