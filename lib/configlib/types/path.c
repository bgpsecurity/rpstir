#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "util/path_compat.h"

#include "path.h"


bool config_type_path_converter(
    const struct config_context * context,
    void *usr_arg,
    const char *input,
    void **data)
{
    (void)usr_arg;

    if (input == NULL)
    {
        config_message(context, LOG_ERR,
                       "paths can't be empty. "
                       "Use `.' to specify the current directory");
        return false;
    }

    *data = realpath(input, NULL);
    if (*data == NULL)
    {
        config_message(context, LOG_ERR, "realpath(): %s", strerror(errno));
        return false;
    }

    return true;
}
