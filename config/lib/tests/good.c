#include "unittest.h"
#include "logging.h"

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
		config_type_sscanf_converter, &config_type_sscanf_arg_int,
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
		config_type_sscanf_converter, &config_type_sscanf_arg_int,
		free,
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
		config_type_sscanf_converter, &config_type_sscanf_arg_int,
		free,
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
		config_type_sscanf_converter, &config_type_sscanf_arg_int,
		free,
		NULL, NULL,
		"-1 0 1"
	},

	// CONFIG_DEFAULT_EMPTY_ARRAY
	{
		"DefaultEmptyArray",
		true,
		config_type_sscanf_converter, &config_type_sscanf_arg_int,
		free,
		NULL, NULL,
		""
	},
};


static bool test_config(const char * conf_file)
{
	bool ret;

	ret = config_load(CONFIG_NUM_OPTIONS, CONFIG_OPTIONS, conf_file);
	TEST_BOOL(ret, true);

	TEST(int, "%d", *(const int *)config_get(CONFIG_SOME_INT), ==, -5);

	TEST(size_t, "%zu", config_get_length(CONFIG_EMPTY_ARRAY), ==, 0);

	TEST(size_t, "%zu", config_get_length(CONFIG_STRING_ARRAY), ==, 3);
	TEST_STR(((char const * const *)config_get_array(CONFIG_STRING_ARRAY))[0], ==, "foo");
	TEST_STR(((char const * const *)config_get_array(CONFIG_STRING_ARRAY))[1], ==, "bar");
	TEST_STR(((char const * const *)config_get_array(CONFIG_STRING_ARRAY))[2], ==, "quux");

	TEST(size_t, "%zu", config_get_length(CONFIG_INT_ARRAY), ==, 4);
	TEST(int, "%d", *((int const * const *)config_get_array(CONFIG_INT_ARRAY))[0], ==, 8);
	TEST(int, "%d", *((int const * const *)config_get_array(CONFIG_INT_ARRAY))[1], ==, -3);
	TEST(int, "%d", *((int const * const *)config_get_array(CONFIG_INT_ARRAY))[2], ==, 40);
	TEST(int, "%d", *((int const * const *)config_get_array(CONFIG_INT_ARRAY))[3], ==, 0xff);

	TEST(size_t, "%zu", config_get_length(CONFIG_LONG_ARRAY), ==, 5);
	TEST_STR(((char const * const *)config_get_array(CONFIG_LONG_ARRAY))[0], ==, "foo");
	TEST_STR(((char const * const *)config_get_array(CONFIG_LONG_ARRAY))[1], ==, "bar");
	TEST_STR(((char const * const *)config_get_array(CONFIG_LONG_ARRAY))[2], ==, "quux");
	TEST_STR(((char const * const *)config_get_array(CONFIG_LONG_ARRAY))[3], ==, "baz");
	TEST_STR(((char const * const *)config_get_array(CONFIG_LONG_ARRAY))[4], ==, "something");

	TEST(int, "%d", *(const int *)config_get(CONFIG_INCLUDED_INT), ==, 42);

	TEST_STR((const char *)config_get(CONFIG_DEFAULT_STRING), ==, "this-is-the-default");

	TEST(size_t, "%zu", config_get_length(CONFIG_DEFAULT_INT_ARRAY), ==, 3);
	TEST(int, "%d", *((int const * const *)config_get_array(CONFIG_DEFAULT_INT_ARRAY))[0], ==, -1);
	TEST(int, "%d", *((int const * const *)config_get_array(CONFIG_DEFAULT_INT_ARRAY))[1], ==, 0);
	TEST(int, "%d", *((int const * const *)config_get_array(CONFIG_DEFAULT_INT_ARRAY))[2], ==, 1);

	TEST(size_t, "%zu", config_get_length(CONFIG_DEFAULT_EMPTY_ARRAY), ==, 0);

	config_unload();

	return true;
}


int main(int argc, char **argv)
{
	int retval = EXIT_SUCCESS;

	(void)argc;

	OPEN_LOG("config-test-good", LOG_USER);

	char * conf_file = malloc(strlen(argv[0]) + strlen(".conf") + 1);
	if (conf_file == NULL)
	{
		fprintf(stderr, "out of memory\n");
		return EXIT_FAILURE;
	}

	snprintf(conf_file,
		strlen(argv[0]) + strlen(".conf") + 1,
		"%s.conf",
		argv[0]);

	if (!test_config(conf_file))
	{
		retval = EXIT_FAILURE;
	}

	free(conf_file);

	CLOSE_LOG();

	return retval;
}
