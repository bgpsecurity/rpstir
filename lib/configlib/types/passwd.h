#ifndef _LIB_CONFIGLIB_TYPES_PASSWD_H
#define _LIB_CONFIGLIB_TYPES_PASSWD_H

#include "configlib/configlib.h"

struct passwd config_type_passwd_converter(
	const struct config_context *context,
    void *usr_arg,
    const char *input,
    void **data);

struct config_type_passwd_usr_arg {
    bool allow_null;
};

#endif