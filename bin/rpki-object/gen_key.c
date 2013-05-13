#include <unistd.h>
#include <stdio.h>
#include "util/cryptlib_compat.h"
#include <string.h>

/*
 * $Id: genkey.c 506 2008-06-03 21:20:05Z gardiner $ 
 */

#define STANDARD_KEY_SIZE 2048


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
    if (ksize != STANDARD_KEY_SIZE)
    {
        fprintf(stderr, "Warning: key size %d is not the standard size (%d)\n",
                ksize, STANDARD_KEY_SIZE);
    }
    printf("Making %s with key size %d bits \n", argv[1], ksize);
    if (cryptInit() != CRYPT_OK)
    {
        fprintf(stderr, "Can't open Cryptlib\n");
        return 1;
    }
    if (cryptCreateContext(&privKeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA) != CRYPT_OK)
    {
        fprintf(stderr, "Can't create cryptlib private key context\n");
        return 1;
    }
    cryptSetAttributeString(privKeyContext, CRYPT_CTXINFO_LABEL, "label", 5);
    cryptSetAttribute(privKeyContext, CRYPT_CTXINFO_KEYSIZE, ksize / 8);
    if (cryptGenerateKey(privKeyContext) != CRYPT_OK)
    {
        fprintf(stderr, "Can't generate key\n");
        return 1;
    }
    if (cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
                    argv[1], CRYPT_KEYOPT_CREATE) != CRYPT_OK)
    {
        fprintf(stderr, "Can't open keyset\n");
        return 1;
    }
    if (cryptAddPrivateKey(cryptKeyset, privKeyContext, "password") != CRYPT_OK)
    {
        fprintf(stderr, "Can't add key to keyset\n");
        return 1;
    }
    cryptKeysetClose(cryptKeyset);
    cryptDestroyContext(privKeyContext);
    cryptEnd();

    return 0;
}
