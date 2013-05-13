#include <syslog.h>
#include <string.h>

#include "enum.h"

bool config_type_enum_converter(
    const struct config_context *context,
    void *usr_arg,
    const char *input,
    void **data)
{
    struct config_type_enum_usr_arg_item *args =
        (struct config_type_enum_usr_arg_item *)usr_arg;
    size_t i;

    if (input == NULL)
    {
        config_message(context, LOG_ERR, "enumerated types can't be empty");
        return false;
    }

    for (i = 0; args[i].name != NULL; ++i)
    {
        if (strcmp(args[i].name, input) == 0)
        {
            *data = args[i].value;
            return true;
        }
    }

    config_message(context, LOG_ERR, "unrecognized value");
    config_message(context, LOG_INFO, "recognized values are:");
    for (i = 0; args[i].name != NULL; ++i)
    {
        config_message(context, LOG_INFO, "%s", args[i].name);
    }

    return false;
}


static int log_level_value_emerg = LOG_EMERG;
static int log_level_value_alert = LOG_ALERT;
static int log_level_value_crit = LOG_CRIT;
static int log_level_value_err = LOG_ERR;
static int log_level_value_warning = LOG_WARNING;
static int log_level_value_notice = LOG_NOTICE;
static int log_level_value_info = LOG_INFO;
static int log_level_value_debug = LOG_DEBUG;
struct config_type_enum_usr_arg_item config_type_enum_arg_log_level[] = {
    {"LOG_EMERG", &log_level_value_emerg},
    {"LOG_ALERT", &log_level_value_alert},
    {"LOG_CRIT", &log_level_value_crit},
    {"LOG_ERR", &log_level_value_err},
    {"LOG_WARNING", &log_level_value_warning},
    {"LOG_NOTICE", &log_level_value_notice},
    {"LOG_INFO", &log_level_value_info},
    {"LOG_DEBUG", &log_level_value_debug},
    {NULL, NULL},
};


void config_type_enum_free(
    void *data)
{
    // Don't do anything because data is a pointer to a global variable.
    (void)data;
}
