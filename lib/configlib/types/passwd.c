#include <stdio.h>
#include <pwd.h>

#include "passwd.h"

bool config_type_passwd_converter(
	const struct config_context *context,
    void *usr_arg,
    const char *input,
    void **data)
{

	struct config_type_passwd_usr_arg * args =
        (struct config_type_passwd_usr_arg *)usr_arg;

    if (input == NULL)
    {
        if (args->allow_null)
        {
            if (!config_context_is_default(context))
            {
                config_message(context, LOG_DEBUG,
                               "found NULL option. If you meant the empty "
                               "string, use `\"\"' instead");
            }
            *data = NULL;
            return true;
        }
        else
        {
            config_message(context, LOG_ERR,
                           "this option can't be NULL. "
                           "For the empty string, use `\"\"'");
            return false;
        }
    }
	
	struct passwd *pwd;
	pwd = getpwnam(input);

	if (pwd == NULL)
	{
		int uid;
		if (sscanf(input, "%d", &uid) == 0)
		{
			LOG(LOG_ERR, "can't find user: %s", input);
			return false;
		}

		pwd = getpwuid(uid);
		if (pwd == NULL)
		{
			LOG(LOG_ERR, "can't find user: %d", uid);
			return false;
		}
	}

	*data = pwd;
	if (*data == NULL)
    {
        LOG(LOG_ERR, "out of memory");
        return false;
    }

	return true;
}

struct config_type_passwd_usr_arg config_type_passwd_arg_optional = {true};

struct config_type_passwd_usr_arg config_type_passwd_arg_mandatory = {false};

void config_type_passwd_free(void *data)
{
	(void)data;
}