#ifndef _LIB_CONFIGLIB_TYPES_BOOL_H
#define _LIB_CONFIGLIB_TYPES_BOOL_H

#include "configlib/configlib.h"

bool config_type_bool_converter(
    const struct config_context *context,
    void *usr_arg,
    const char *input,
    void **data);

#endif
