#include "string.h"

bool config_type_string_converter(const config_context_t context, void * usr_arg, const char * input, void ** data)
{
	*data = strdup(input);
	if (*data == NULL)
	{
		LOG(LOG_ERR, "out of memory");
		return false;
	}

	return true;
}
