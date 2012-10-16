#ifndef _LIB_CONFIGLIG_TYPES_ENUM_H
#define _LIB_CONFIGLIG_TYPES_ENUM_H

#include "configlib/configlib.h"

bool config_type_enum_converter(
    const struct config_context *context,
    void *usr_arg,
    const char *input,
    void **data);

/**
    usr_arg is an array of these. The last item in the array must be
    (NULL, NULL).
*/
struct config_type_enum_usr_arg_item {
    const char * name;
    void * value;
};

/** syslog() log levels. Value type is int. */
extern struct config_type_enum_usr_arg_item config_type_enum_arg_log_level[];


void config_type_enum_free(
    void *data);

#endif
