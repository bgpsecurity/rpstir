#ifndef _LIB_CONFIG_TYPES_PATH_H
#define _LIB_CONFIG_TYPES_PATH_H

#include "lib/configlib.h"

bool config_type_path_converter(
    const struct config_context *context,
    void *usr_arg,
    const char *input,
    void **data);

#endif
