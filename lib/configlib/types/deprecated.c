#include "deprecated.h"
#include "util/logging.h"

_Bool
config_type_deprecated_converter(
    const struct config_context *context,
    void *usr_arg,
    const char *input,
    void **data)
{
    (void)usr_arg;
    (void)input;
    if (!config_context_is_default(context))
    {
        config_message(context, LOG_WARNING,
                       "this option is deprecated and has no effect");
    }
    *data = NULL;
    return 1;
}
