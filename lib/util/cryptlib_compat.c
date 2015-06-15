#include <pthread.h>

#define COMPAT_NO_CLOBBER
#include "cryptlib_compat.h"


static pthread_once_t cryptInit_called = PTHREAD_ONCE_INIT;
static volatile C_RET cryptInit_ret;

static void cryptInit_once_routine()
{
    cryptInit_ret = cryptInit();
}

C_CHECK_RETVAL \
C_RET cryptInit_wrapper()
{
    int ret = pthread_once(&cryptInit_called, cryptInit_once_routine);
    if (ret != 0)
    {
        return CRYPT_ERROR_FAILED;
    }

    if (cryptInit_ret == CRYPT_ERROR_INITED)
    {
        return CRYPT_OK;
    }

    return cryptInit_ret;
}

