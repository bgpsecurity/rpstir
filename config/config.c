#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "logging.h"

#include "config.h"
#include "config_type.h"
#include "config_parse.h"

#include "types/string.h"


#define CONFIG_ENV_VAR PACKAGE_NAME_UC "_CONFIG"


/** All available config options */
static const struct config_option config_options[] = {
	// CONFIG_ROOT
	{
		"Root",
		false,
		config_type_string_converter, NULL,
		free,
		NULL, NULL,
		ABS_TOP_SRCDIR
	},
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


void config_mesage(const config_context_t context_voidp, int priority, const char * format, ...)
{
	struct config_context * context;
	va_list ap;
	char message[512];

	va_start(ap, format);
	vsnprintf(message, sizeof(message), format, ap);
	va_end(ap);

	// modelled after gcc error messages for included files
	for (context = (struct config_context *)context_voidp;
		context != NULL;
		context = context->includes)
	{
		if (context->includes != NULL && context->includes->line != 0)
		{
			LOG(priority, "In config file included from %s:%zu:",
				context->file, context->line);
		}
		else if (context->line != 0)
		{
			LOG(priority, "%s:%zu: %s", context->file, context->line, message);
			break;
		}
		else
		{
			LOG(priority, "%s", message);
			break;
		}
	}
}

bool config_load(const char * filename)
{
	if (filename == NULL)
	{
		filename = getenv(CONFIG_ENV_VAR);
		if (filename != NULL)
		{
			LOG(LOG_DEBUG, "using configuration file \"%s\" from environment variable %s",
				filename, CONFIG_ENV_VAR);
		}
	}

	if (filename == NULL)
	{
		filename = DEFAULT_CONFIG_FILE;
		LOG(LOG_DEBUG, "using default configuration file \"%s\"", filename);
	}

	struct config_context context;
	context.filename = filename;
	context.line = 0;
	context.includes = NULL;

	return config_parse_file(config_options, config_values, &context, &context);
}

void config_unload()
{
	size_t i, j;

	for (i = 0; i < CONFIG_NUM_ITEMS; ++i)
	{
		if (config_options[i].is_array)
		{
			for (j = 0; j < config_values[i].array_value.num_items; ++j)
			{
				config_options[i].value_free(config_values[i].array_value.data[j]);
			}
			free(config_values[i].array_value.data);
		}
		else
		{
			config_options[i].value_free(config_values[i].single_value.data);
		}
	}
}
