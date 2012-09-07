#include <unistd.h>
#include <stdio.h>
#include "util/cryptlib_compat.h"
#include <string.h>

/*
 * $Id: genkey.c 506 2008-06-03 21:20:05Z gardiner $ 
 */


int main(
    int argc,
    char **argv)
{
    CRYPT_CONTEXT privKeyContext;
    CRYPT_KEYSET cryptKeyset;
    int ksize;
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s filename keysize\n", argv[0]);
        return 1;
    }
    if (sscanf(argv[2], "%d", &ksize) != 1)
    {
        fprintf(stderr, "Invalid key size\n");
        return 1;
    }
    printf("Making %s with key size %d bits \n", argv[1], ksize);
    if (cryptInit() != CRYPT_OK)
    {
        fprintf(stderr, "Can't open Cryptlib\n");
        return 1;
    }
    cryptCreateContext(&privKeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA);
    cryptSetAttributeString(privKeyContext, CRYPT_CTXINFO_LABEL, "label", 5);
    cryptSetAttribute(privKeyContext, CRYPT_CTXINFO_KEYSIZE, ksize / 8);
    cryptGenerateKey(privKeyContext);
    cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
                    argv[1], CRYPT_KEYOPT_CREATE);
    cryptAddPrivateKey(cryptKeyset, privKeyContext, "password");
    cryptKeysetClose(cryptKeyset);
    cryptDestroyContext(privKeyContext);
    cryptEnd();

    return 0;
}
