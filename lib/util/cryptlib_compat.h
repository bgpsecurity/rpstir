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
C_RET cryptInit_wrapper();

#ifndef COMPAT_NO_CLOBBER
#define cryptInit cryptInit_wrapper
#endif


#endif
