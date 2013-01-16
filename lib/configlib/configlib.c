#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "util/logging.h"

#include "configlib.h"
#include "config_load.h"


static size_t config_num_options = 0;
static const struct config_option *config_options = NULL;
static struct config_value *config_values = NULL;


bool config_is_array(
    size_t key)
{
    return config_options[key].is_array;
}

const void *config_get(
    size_t key)
{
    return config_values[key].value.single_value.data;
}

char * config_get_string(
    size_t key)
{
    if (config_options[key].value_convert_inverse == NULL)
    {
        LOG(LOG_ERR, "configuration option %s's type does not support "
            "converting to a string", config_options[key].name);
        return NULL;
    }

    return config_options[key].value_convert_inverse(
        config_options[key].value_convert_inverse_usr_arg,
        config_values[key].single_value.data);
}

size_t config_get_length(
    size_t key)
{
    return config_values[key].value.array_value.num_items;
}

void const *const *config_get_array(
    size_t key)
{
    return (void const *const *)config_values[key].value.array_value.data;
}

char ** config_get_string_array(
    size_t key)
{
    size_t i;

    if (config_options[key].value_convert_inverse == NULL)
    {
        LOG(LOG_ERR, "configuration option %s's type does not support "
            "converting to a string", config_options[key].name);
        return NULL;
    }

    if (config_values[key].array_value.num_items == 0)
    {
        return NULL;
    }

    char ** ret = calloc(config_values[key].array_value.num_items,
                         sizeof(char *));
    if (ret == NULL)
    {
        LOG(LOG_ERR, "out of memory");
        goto err;
    }

    for (i = 0; i < config_values[key].array_value.num_items; ++i)
    {
        ret[i] = config_options[key].value_convert_inverse(
            config_options[key].value_convert_inverse_usr_arg,
            config_values[key].array_value.data[i]);
        if (ret[i] == NULL)
        {
            goto err;
        }
    }

    return ret;

err:
    if (ret != NULL)
    {
        for (i = 0; i < config_values[key].array_value.num_items; ++i)
        {
            free(ret[i]);
        }
        free(ret);
    }

    return NULL;
}

ssize_t config_find(
    const char * name)
{
    size_t key;

    for (key = 0; key < config_num_options; ++key)
    {
        if (strcmp(config_options[key].name, name) == 0)
        {
            return (ssize_t)key;
        }
    }

    LOG(LOG_ERR, "configuration option %s not found", name);
    return -1;
}


bool config_context_is_default(
    const struct config_context * context)
{
    return context->is_default;
}


void config_message(
    const struct config_context *context,
    int priority,
    const char *format,
    ...)
{
    va_list ap;
    char message[512];

    va_start(ap, format);
    vsnprintf(message, sizeof(message), format, ap);
    va_end(ap);

    if (context->is_default)
    {
        LOG(priority, "default value for %s: %s",
            context->context.default_context.option, message);
    }
    else
    {
        const struct config_context_file * file_context;

        // modelled after gcc error messages for included files
        for (file_context = &context->context.file_context;
            file_context != NULL;
            file_context = file_context->includes)
        {
            if (file_context->includes != NULL && file_context->includes->line != 0)
            {
                LOG(priority, "In config file included from %s:%zu:",
                    file_context->file, file_context->line);
            }
            else if (file_context->file != NULL && file_context->line != 0)
            {
                LOG(priority, "%s:%zu: %s", file_context->file,
                    file_context->line, message);
                break;
            }
            else
            {
                LOG(priority, "%s", message);
                break;
            }
        }
    }
}

bool config_load(
    size_t num_options,
    const struct config_option *options,
    const char *filename,
    char const * const * default_filenames)
{
    size_t i;

    config_num_options = num_options;
    config_options = options;

    config_values = malloc(sizeof(struct config_value) * config_num_options);
    if (config_values == NULL)
    {
        LOG(LOG_ERR, "out of memory");
        config_num_options = 0;
        config_options = NULL;
        return false;
    }

    for (i = 0;
        filename == NULL &&
            default_filenames != NULL &&
            default_filenames[i] != NULL;
        ++i)
    {
        if (access(default_filenames[i], R_OK) == 0)
        {
            filename = default_filenames[i];
            break;
        }
        else if (errno == ENOENT)
        {
            LOG(LOG_DEBUG,
                "Configuration file \"%s\" does not exist, skipping...",
                default_filenames[i]);
        }
        else
        {
            LOG(LOG_ERR, "Error accessing configuration file \"%s\": %s",
                default_filenames[i], strerror(errno));
            config_num_options = 0;
            config_options = NULL;
            free(config_values);
            config_values = NULL;
            return false;
        }
    }

    if (!config_load_defaults
        (config_num_options, config_options, config_values))
    {
        LOG(LOG_ERR, "couldn't load configuration defaults");
        config_unload();
        return false;
    }

    struct config_context context;
    context.is_default = false;

    if (filename == NULL)
    {
        LOG(LOG_DEBUG, "no configuration file specified or available");
    }
    else
    {
        context.context.file_context.file = filename;
        context.context.file_context.line = 0;
        context.context.file_context.includes = NULL;

        if (!config_parse_file
            (config_num_options, config_options, config_values, &context,
             &context.context.file_context))
        {
            config_unload();
            return false;
        }
    }

    for (i = 0; i < config_num_options; ++i)
    {
        if (!config_values[i].filled)
        {
            LOG(LOG_ERR, "option %s must be set", config_options[i].name);
            config_unload();
            return false;
        }
    }

    return true;
}

void config_unload(
    )
{
    size_t i,
        j;

    for (i = 0; i < config_num_options; ++i)
    {
        if (config_options[i].is_array)
        {
            for (j = 0; j < config_values[i].value.array_value.num_items; ++j)
            {
                config_options[i].value_free(config_values[i].value.array_value.
                                             data[j]);
            }
            free(config_values[i].value.array_value.data);
        }
        else
        {
            config_options[i].value_free(config_values[i].value.single_value.data);
        }
    }

    free(config_values);
    config_values = NULL;

    config_options = NULL;

    config_num_options = 0;
}
