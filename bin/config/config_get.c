#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "util/logging.h"
#include "config/config.h"


static bool print_config(size_t key)
{
    if (config_is_array(key))
    {
        size_t i;
        char ** values;

        values = config_get_string_array(key);
        if (values == NULL)
        {
            return false;
        }

        for (i = 0; i < config_get_length(key); ++i)
        {
            printf("%s%c", values[i], '\0');
            free(values[i]);
        }

        free(values);

        return true;
    }
    else
    {
        char * value;

        value = config_get_string(key);
        if (value == NULL)
        {
            return false;
        }

        printf("%s", value);

        free(value);

        return true;
    }
}

int main(
    int argc,
    char **argv)
{
    int ret = EXIT_SUCCESS;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <configuration key>\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Print a textual representation of the value\n");
        fprintf(stderr, "for the specified key.\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "If the value is a scalar, just print it. If it's\n");
        fprintf(stderr, "an array, print each element followed by a NUL.\n");
        exit(EXIT_FAILURE);
    }

    const char * config_key_name = argv[1];

    OPEN_LOG("config_get", LOG_USER);

    bool config_loaded = false;
    ssize_t config_key;

    if (my_config_load())
    {
        config_loaded = true;
    }
    else
    {
        LOG(LOG_ERR, "can't load configuration");
        ret = EXIT_FAILURE;
        goto done;
    }

    config_key = config_find(config_key_name);
    if (config_key < 0)
    {
        ret = EXIT_FAILURE;
        goto done;
    }

    if (!print_config((size_t)config_key))
    {
        ret = EXIT_FAILURE;
        goto done;
    }

done:

    if (config_loaded)
    {
        config_unload();
    }

    CLOSE_LOG();

    return ret;
}
