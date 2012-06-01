#ifndef _CONFIG_TYPES_SSCANF_H
#define _CONFIG_TYPES_SSCANF_H

bool config_type_sscanf_converter(const config_context_t context, void * usr_arg, const char * input, const void ** data);

struct config_type_sscanf_usr_arg {
	const char * scan_format; // e.g. SCNu16. note that this does not include the '%' character
	size_t allocate_length;
	const char * description; // e.g. "an integer between 0 and 255 inclusive"
};

const struct config_type_sscanf_usr_arg config_type_sscanf_arg_uint16_t;
const struct config_type_sscanf_usr_arg config_type_sscanf_arg_size_t;

#endif
