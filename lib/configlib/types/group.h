#ifndef _LIB_CONFIGLIB_TYPES_GROUP_H
#define _LIB_CONFIGLIB_TYPES_GROUP_H

#include "configlib/configlib.h"

bool config_type_group_converter(
	const struct config_context *context,
    void *usr_arg,
    const char *input,
    void **data);

struct config_type_group_usr_arg {
    bool allow_null;
};

struct config_type_group_usr_arg config_type_group_arg_optional;
struct config_type_group_usr_arg config_type_group_arg_mandatory;

void config_type_group_free(void *data);

#endif