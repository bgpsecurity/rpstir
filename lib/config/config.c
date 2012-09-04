#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "configlib/types/path.h"
#include "configlib/types/sscanf.h"
#include "configlib/types/string.h"

#include "config.h"


#define CONFIG_ENV_VAR PACKAGE_NAME_UC "_CONFIG"


/** All available config options */
static const struct config_option config_options[] = {
    // CONFIG_ROOT_DIR
    {
     "RootDir",
     false,
     config_type_path_converter, NULL,
     config_type_path_converter_inverse, NULL,
     free,
     NULL, NULL,
     "\"" ABS_TOP_SRCDIR "\""},

    // CONFIG_RPKI_PORT
    {
     "RPKIPort",
     false,
     config_type_sscanf_converter, &config_type_sscanf_arg_uint16_t,
     config_type_sscanf_converter_inverse, &config_type_sscanf_inverse_arg_uint16_t,
     free,
     NULL, NULL,
     "7344"},

    // CONFIG_DATABASE
    {
     "Database",
     false,
     config_type_string_converter, &config_type_string_arg_mandatory,
     NULL, NULL,
     free,
     NULL, NULL,
     NULL},

    // CONFIG_DATABASE_USER
    {
     "DatabaseUser",
     false,
     config_type_string_converter, &config_type_string_arg_mandatory,
     NULL, NULL,
     free,
     NULL, NULL,
     NULL},

    // CONFIG_DATABASE_PASSWORD
    {
     "DatabasePassword",
     false,
     config_type_string_converter, &config_type_string_arg_optional,
     NULL, NULL,
     free,
     NULL, NULL,
     NULL},

    // CONFIG_DATABASE_DSN
    {
     "DatabaseDSN",
     false,
     config_type_string_converter, &config_type_string_arg_mandatory,
     NULL, NULL,
     free,
     NULL, NULL,
     NULL},

    // CONFIG_DOWNLOAD_CONCURRENCY
    {
     "DownloadConcurrency",
     false,
     config_type_sscanf_converter, &config_type_sscanf_arg_size_t,
     config_type_sscanf_converter_inverse, &config_type_sscanf_inverse_arg_size_t,
     free,
     NULL, NULL,
     "24"},

    // CONFIG_RSYNC_LISTEN_PORT
    {
     "RsyncListenPort",
     false,
     config_type_sscanf_converter, &config_type_sscanf_arg_uint16_t,
     config_type_sscanf_converter_inverse, &config_type_sscanf_inverse_arg_uint16_t,
     free,
     NULL, NULL,
     "3450"},
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
