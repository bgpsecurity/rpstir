#ifndef _LIB_CONFIGLIB_TYPES_STRING_H
#define _LIB_CONFIGLIB_TYPES_STRING_H

#include "configlib/configlib.h"

bool config_type_string_converter(
    const struct config_context *context,
    void *usr_arg,
    const char *input,
    void **data);

struct config_type_string_usr_arg {
    bool allow_null;
};

struct config_type_string_usr_arg config_type_string_arg_optional;
struct config_type_string_usr_arg config_type_string_arg_mandatory;

#endif
