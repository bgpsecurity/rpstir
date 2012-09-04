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

    if (input == NULL)
    {
        config_message(context, LOG_ERR, "%s can't be empty",
                       args->description);
        return false;
    }

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


char * config_type_sscanf_converter_inverse(
    void *usr_arg,
    void *input)
{
    struct config_type_sscanf_inverse_usr_arg *args =
        (struct config_type_sscanf_inverse_usr_arg *)usr_arg;

    if (input == NULL)
    {
        LOG(LOG_ERR, "got NULL input");
        return NULL;
    }

    switch (args->type)
    {
        case CONFIG_TYPE_SSCANF_SIGNED_INT:
        {
            intmax_t value;
            switch (args->size)
            {
                case 1:
                    value = (intmax_t)(*(int8_t *)input);
                    break;
                case 2:
                    value = (intmax_t)(*(int16_t *)input);
                    break;
                case 4:
                    value = (intmax_t)(*(int32_t *)input);
                    break;
                case 8:
                    value = (intmax_t)(*(int64_t *)input);
                    break;
                default:
                    LOG(LOG_ERR, "unknown size of signed integer (%zu)", args->size);
                    return NULL;
            }

            size_t output_size = 1 + 3*sizeof(intmax_t) + 1;
            char * output = malloc(output_size);
            if (output == NULL)
            {
                LOG(LOG_ERR, "out of memory");
                return NULL;
            }
            snprintf(output, output_size, "%" PRIdMAX, value);
            return output;
        }

        case CONFIG_TYPE_SSCANF_UNSIGNED_INT:
        {
            uintmax_t value;
            switch (args->size)
            {
                case 1:
                    value = (uintmax_t)(*(uint8_t *)input);
                    break;
                case 2:
                    value = (uintmax_t)(*(uint16_t *)input);
                    break;
                case 4:
                    value = (uintmax_t)(*(uint32_t *)input);
                    break;
                case 8:
                    value = (uintmax_t)(*(uint64_t *)input);
                    break;
                default:
                    LOG(LOG_ERR, "unknown size of unsigned integer (%zu)", args->size);
                    return NULL;
            }

            size_t output_size = 3*sizeof(uintmax_t) + 1;
            char * output = malloc(output_size);
            if (output == NULL)
            {
                LOG(LOG_ERR, "out of memory");
                return NULL;
            }
            snprintf(output, output_size, "%" PRIuMAX, value);
            return output;
        }

        default:
            LOG(LOG_ERR, "unknown type (%d)", args->type);
            return NULL;
    }
}

struct config_type_sscanf_inverse_usr_arg config_type_sscanf_inverse_arg_size_t =
    { CONFIG_TYPE_SSCANF_UNSIGNED_INT, sizeof(size_t) };
struct config_type_sscanf_inverse_usr_arg config_type_sscanf_inverse_arg_uint16_t =
    { CONFIG_TYPE_SSCANF_UNSIGNED_INT, sizeof(uint16_t) };
