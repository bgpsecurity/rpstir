#include <stdio.h>
#include <util/cryptlib_compat.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int CryptInitState = 0;

int gen_hash(
    unsigned char *inbufp,
    int bsize,
    unsigned char *outbufp,
    CRYPT_ALGO_TYPE alg)
{
    CRYPT_CONTEXT hashContext;
    unsigned char hash[40];
    int ansr = -1;

    if (alg != CRYPT_ALGO_SHA && alg != CRYPT_ALGO_SHA2)
        return -1;
    memset(hash, 0, 40);
    if (!CryptInitState)
    {
        if (cryptInit() != CRYPT_OK)
            return -1;
        CryptInitState = 1;
    }

    if (cryptCreateContext(&hashContext, CRYPT_UNUSED, alg) != CRYPT_OK)
        return -1;
    cryptEncrypt(hashContext, inbufp, bsize);
    cryptEncrypt(hashContext, inbufp, 0);
    cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ansr);
    cryptDestroyContext(hashContext);
    if (ansr > 0)
        memcpy(outbufp, hash, ansr);
    return ansr;
}
