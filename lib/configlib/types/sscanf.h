#ifndef _LIB_CONFIGLIB_TYPES_SSCANF_H
#define _LIB_CONFIGLIB_TYPES_SSCANF_H

#include "configlib/configlib.h"

bool config_type_sscanf_converter(
    const struct config_context *context,
    void *usr_arg,
    const char *input,
    void **data);

struct config_type_sscanf_usr_arg {
    const char *scan_format;    // e.g. SCNu16. note that this does not
                                // include the '%' character
    size_t allocate_length;
    const char *description;    // e.g. "an integer between 0 and 255
                                // inclusive"
};

struct config_type_sscanf_usr_arg config_type_sscanf_arg_int;
struct config_type_sscanf_usr_arg config_type_sscanf_arg_uint16_t;
struct config_type_sscanf_usr_arg config_type_sscanf_arg_size_t;


char * config_type_sscanf_converter_inverse(
    void *usr_arg,
    void *input);

struct config_type_sscanf_inverse_usr_arg {
    enum {
        CONFIG_TYPE_SSCANF_SIGNED_INT,
        CONFIG_TYPE_SSCANF_UNSIGNED_INT,
        // TODO: relevant types for any other config_type_sscanf_arg_foo
        //       variables above
    } type;

    size_t size;
};

struct config_type_sscanf_inverse_usr_arg config_type_sscanf_inverse_arg_uint16_t;

#endif
