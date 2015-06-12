#ifndef _LIB_CONFIGLIB_TYPES_PASSWD_H
#define _LIB_CONFIGLIB_TYPES_PASSWD_H

#include "configlib/configlib.h"

bool config_type_passwd_converter(
	const struct config_context *context,
    void *usr_arg,
    const char *input,
    void **data);

struct config_type_passwd_usr_arg {
    bool allow_null;
};

struct config_type_passwd_usr_arg config_type_passwd_arg_optional;
struct config_type_passwd_usr_arg config_type_passwd_arg_mandatory;

void config_type_passwd_free(void *data);

#endif