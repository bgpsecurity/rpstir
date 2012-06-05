#ifndef _CONFIG_TYPES_STRING_H
#define _CONFIG_TYPES_STRING_H

#include "config_type.h"

bool config_type_string_converter(const struct config_context * context, void * usr_arg, const char * input, void ** data);

#endif
