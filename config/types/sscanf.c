#include "sscanf.h"

bool config_type_sscanf_converter(void * usr_arg, const char * input, const void ** data)
{
	struct converter_sscanf_usr_arg * args = (struct converter_sscanf_usr_arg *)usr_arg;
	char scan_format[32];
	int consumed;

	*data = malloc(args->allocate_length);
	if (*data == NULL)
	{
		LOG(LOG_ERR, "out of memory");
		return false;
	}

	if (snprintf(scan_format, sizeof(scan_format), "%%%s%%n", args->scan_format) >= sizeof(scan_format))
	{
		LOG(LOG_ERR, "scan_format too long: %s", args->scan_format);
		free(*data);
		return false;
	}

	if (sscanf(input, scan_format, *data, &consumed) < 1 ||
		consumed < strlen(input))
	{
		LOG(LOG_ERR, "Invalid value: %s", input);
		free(*data);
		return false;
	}

	return true;
}

const struct config_type_sscanf_usr_arg config_type_sscanf_arg_uint16_t = {SCNu16, sizeof(uint16_t)};
const struct config_type_sscanf_usr_arg config_type_sscanf_arg_size_t = {"zu", sizeof(size_t)};
