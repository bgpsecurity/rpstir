#include "cryptlib_compat.h"

#include "util/logging.h"

#include <pthread.h>
#include <stdlib.h>


static pthread_once_t cryptInit_called = PTHREAD_ONCE_INIT;
static volatile C_RET cryptInit_ret;

static void
cryptlib_atexit_handler(
    void)
{
    cryptEnd();
}

static void
cryptInit_once_routine(
    void)
{
    cryptInit_ret = cryptInit();
    if (CRYPT_OK == cryptInit_ret)
    {
        if (atexit(&cryptlib_atexit_handler))
        {
            LOG(LOG_ERR, "failed to register cryptEnd() atexit() handler");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        LOG(LOG_NOTICE, "cryptInit() did not return CRYPT_OK;"
            " not registering cryptEnd() atexit() handler");
    }
}

C_CHECK_RETVAL \
C_RET cryptInit_wrapper()
{
    int ret = pthread_once(&cryptInit_called, &cryptInit_once_routine);
    if (ret != 0)
    {
        ERR_LOG(ret, NULL, "pthread_once(..., &cryptInit_once_routine) failed");
        return CRYPT_ERROR_FAILED;
    }

    if (cryptInit_ret == CRYPT_ERROR_INITED)
    {
        return CRYPT_OK;
    }

    return cryptInit_ret;
}
