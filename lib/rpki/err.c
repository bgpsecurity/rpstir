#include "err.h"

#include <stdio.h>

#define ERROR_ARRAY_DESCR(NAME, DESCR) [POS_##NAME] = DESCR,

/**
 * @brief
 *     array mapping negated error codes to human-friendly
 *     descriptions
 */
static const char *errs[] = {
    ERROR_CODES(ERROR_ARRAY_DESCR)
};

const char *
err2string(
    err_code err)
{
    if (err > 0 || err < ERR_SCM_MAXERR)
        return (NULL);
    return (errs[-err]);
}

#define ERROR_ARRAY_NAME(NAME, DESCR) [POS_##NAME] = #NAME,

/**
 * @brief
 *     array mapping negated error codes to their names
 */
static const char *err_names[] = {
    ERROR_CODES(ERROR_ARRAY_NAME)
};

const char *
err2name(
    err_code err)
{
    if (err > 0 || err < ERR_SCM_MAXERR)
        return (NULL);
    return (err_names[-err]);
}
