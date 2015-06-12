#include <stdio.h>
#include <grp.h>

#include "group.h"

bool config_type_group_converter(
	const struct config_context *context,
    void *usr_arg,
    const char *input,
    void **data)
{

	struct config_type_group_usr_arg * args =
        (struct config_type_group_usr_arg *)usr_arg;

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

	struct group *grp;
	grp = getgrnam(input);

	if (grp == NULL)
	{
        int gid;
        if (sscanf(input, "%d", &gid) == 0)
        {
		  LOG(LOG_ERR, "can't find user: %s", input);
		  return false;
        }

        grp = getgrgid(gid);
        if (grp == NULL)
        {
            LOG(LOG_ERR, "can't find user: %d", gid);
            return false;
        }
	}

	*data = grp;
	if (*data == NULL)
    {
        LOG(LOG_ERR, "out of memory");
        return false;
    }

	return true;
}

struct config_type_group_usr_arg config_type_group_arg_optional = {true};

struct config_type_group_usr_arg config_type_group_arg_mandatory = {false};

void config_type_group_free(void *data)
{
    (void)data;
}