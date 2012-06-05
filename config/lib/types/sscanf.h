#ifndef _LIB_CONFIG_TYPES_SSCANF_H
#define _LIB_CONFIG_TYPES_SSCANF_H

#include "lib/configlib.h"

bool config_type_sscanf_converter(const struct config_context * context, void * usr_arg, const char * input, void ** data);

struct config_type_sscanf_usr_arg {
	const char * scan_format; // e.g. SCNu16. note that this does not include the '%' character
	size_t allocate_length;
	const char * description; // e.g. "an integer between 0 and 255 inclusive"
};

const struct config_type_sscanf_usr_arg config_type_sscanf_arg_int;
const struct config_type_sscanf_usr_arg config_type_sscanf_arg_uint16_t;
const struct config_type_sscanf_usr_arg config_type_sscanf_arg_size_t;

#endif
