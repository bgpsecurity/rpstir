#include <string.h>

#include "bool.h"

static char const * const true_names[] = {
	"true",
	"True",
	"TRUE",
	"t",
	"T",
	"yes",
	"Yes",
	"YES",
	"y",
	"Y",
	"1",
	NULL
};

static char const * const false_names[] = {
	"false",
	"False",
	"FALSE",
	"f",
	"F",
	"no",
	"No",
	"NO",
	"n",
	"N",
	"0",
	NULL
};

bool config_type_bool_converter(
	const struct config_context * context,
	void * usr_arg,
	const char * input,
	void ** data)
{
	size_t i;
	bool val;
	bool found = false;

	(void)usr_arg;

	for (i = 0; !found && true_names[i] != NULL; ++i)
	{
		if (strcmp(true_names[i], input) == 0)
		{
			val = true;
			found = true;
		}
	}

	for (i = 0; !found && false_names[i] != NULL; ++i)
	{
		if (strcmp(false_names[i], input) == 0)
		{
			val = false;
			found = true;
		}
	}

	if (!found)
	{
		config_message(context, LOG_ERR, "invalid value for boolean: %s", input);
		return false;
	}

	*data = malloc(sizeof(bool));
	if (*data == NULL)
	{
		LOG(LOG_ERR, "out of memory");
		return false;
	}

	*((bool *)*data) = val;

	return true;
}
