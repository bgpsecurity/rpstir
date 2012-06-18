#include <stdio.h>
#include <inttypes.h>

#include "sscanf.h"

bool config_type_sscanf_converter(
    const struct config_context * context,
    void *usr_arg,
    const char *input,
    void **data)
{
    struct config_type_sscanf_usr_arg *args =
        (struct config_type_sscanf_usr_arg *)usr_arg;
    char scan_format[32];
    int consumed;

    *data = malloc(args->allocate_length);
    if (*data == NULL)
    {
        LOG(LOG_ERR, "out of memory");
        return false;
    }

    if ((ssize_t)
        snprintf(scan_format, sizeof(scan_format), "%%%s%%n",
                 args->scan_format) >= (ssize_t) sizeof(scan_format))
    {
        LOG(LOG_ERR, "scan_format too long: %s", args->scan_format);
        free(*data);
        return false;
    }

    if (sscanf(input, scan_format, *data, &consumed) < 1 ||
        (size_t) consumed < strlen(input))
    {
        config_message(context, LOG_ERR, "invalid value: %s, should be %s",
                       input, args->description);
        free(*data);
        return false;
    }

    return true;
}

struct config_type_sscanf_usr_arg config_type_sscanf_arg_int =
    { "i", sizeof(int), "an integer" };
struct config_type_sscanf_usr_arg config_type_sscanf_arg_uint16_t =
    { SCNu16, sizeof(uint16_t), "an integer between 0 and 65535 inclusive" };
struct config_type_sscanf_usr_arg config_type_sscanf_arg_size_t =
    { "zu", sizeof(size_t), "a non-negative integer" };
