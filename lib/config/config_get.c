#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "util/logging.h"
#include "config/config.h"

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
        exit(EXIT_FAILURE);
    }

    const char * config_key = argv[1];

    OPEN_LOG(PACKAGE_NAME "-config_get", LOG_USER);

    bool config_loaded = false;
    char * config_value = NULL;

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

    config_value = config_find(config_key);

    if (config_value == NULL)
    {
        ret = EXIT_FAILURE;
        goto done;
    }

    fprintf(stdout, "%s", config_value);

done:

    free(config_value);

    if (config_loaded)
    {
        config_unload();
    }

    CLOSE_LOG();

    return ret;
}
