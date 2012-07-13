#ifndef _CRYPTLIB_COMPAT_H
#define _CRYPTLIB_COMPAT_H

#include <cryptlib.h>


/**
 * Prototype copied from cryptInit() in cryptlib.h.
 *
 * This wrapper handles multiple calls and will return CRYPT_OK even if
 * cryptlib has already been initialized.
 */
C_CHECK_RETVAL \
static inline C_RET cryptInit_wrapper()
{
    C_RET ret = cryptInit();

    if (ret == CRYPT_ERROR_INITED)
    {
        ret = CRYPT_OK;
    }

    return ret;
}

#define cryptInit cryptInit_wrapper


#endif
