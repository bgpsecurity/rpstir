#ifndef _LIB_CONFIGLIB_TYPES_STRING_H
#define _LIB_CONFIGLIB_TYPES_STRING_H

#include "configlib/configlib.h"

bool config_type_string_converter(
    const struct config_context *context,
    void *usr_arg,
    const char *input,
    void **data);

#endif
