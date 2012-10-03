#include "string.h"

bool config_type_string_converter(
    const struct config_context *context,
    void *usr_arg,
    const char *input,
    void **data)
{
    struct config_type_string_usr_arg * args =
        (struct config_type_string_usr_arg *)usr_arg;

    if (input == NULL)
    {
        if (args->allow_null)
        {
            config_message(context, LOG_DEBUG,
                           "found NULL option. "
                           "If you meant the empty string, use `\"\"' instead");
            *data = NULL;
            return true;
        }
        else
        {
            config_message(context, LOG_ERR,
                           "this option can't be NULL. "
                           "For the empty string, use `\"\"'");
            return false;
        }
    }

    *data = strdup(input);
    if (*data == NULL)
    {
        LOG(LOG_ERR, "out of memory");
        return false;
    }

    return true;
}

struct config_type_string_usr_arg config_type_string_arg_optional = {true};

struct config_type_string_usr_arg config_type_string_arg_mandatory = {false};


char * config_type_string_converter_inverse(
    void *usr_arg,
    void *input)
{
    (void)usr_arg;

    if (input == NULL)
    {
        LOG(LOG_ERR, "can't print a NULL string");
        return NULL;
    }

    char * ret = strdup((const char *)input);

    if (ret == NULL)
    {
        LOG(LOG_ERR, "out of memory");
        return NULL;
    }

    return ret;
}
