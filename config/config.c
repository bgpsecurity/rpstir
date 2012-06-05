#include <stdlib.h>

#include "config.h"

#include "lib/types/string.h"


/** All available config options */
const struct config_option CONFIG_OPTIONS[] = {
	// CONFIG_ROOT
	{
		"Root",
		false,
		config_type_string_converter, NULL,
		free,
		NULL, NULL,
		"\"" ABS_TOP_SRCDIR "\""
	},
};
