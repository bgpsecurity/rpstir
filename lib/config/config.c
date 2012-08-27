#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "configlib/types/string.h"

#include "config.h"


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
     "\"" ABS_TOP_SRCDIR "\""},
};


bool my_config_load(
    )
{
    const char * user_home = getenv("HOME");
    if (user_home == NULL)
    {
        LOG(LOG_ERR, "environment variable HOME not set");
        return false;
    }

    char * user_conf_file = NULL;
    size_t user_conf_file_len = strlen(user_home) + strlen("/") +
                                strlen("." PACKAGE_NAME ".conf") + 1;

    user_conf_file = malloc(user_conf_file_len);
    if (user_conf_file == NULL)
    {
        LOG(LOG_ERR, "out of memory");
        return false;
    }

    snprintf(user_conf_file, user_conf_file_len, "%s/.%s.conf", user_home,
             PACKAGE_NAME);

    char const * const default_config_files[] = {
        user_conf_file,
        SYSCONFDIR "/" PACKAGE_NAME ".conf",
        NULL
    };

    bool ret = config_load(CONFIG_NUM_OPTIONS, config_options,
                           getenv(CONFIG_ENV_VAR), default_config_files);

    free(user_conf_file);

    return ret;
}
