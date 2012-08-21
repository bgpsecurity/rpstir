#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include "util/cryptlib_compat.h"
#include <string.h>

/*
 * $Id: genkey.c 506 2008-06-03 21:20:05Z csmall $ 
 */

/*
 * int fatal(char *msg) { if (msg && *msg) fprintf(stderr, "%s\n", msg);
 * exit(0); } 
 */
int main(
    int argc,
    char **argv)
{
    CRYPT_CONTEXT privKeyContext;
    CRYPT_KEYSET cryptKeyset;

    if (argc < 2)
    {
        fprintf(stderr, "Usage: Filename\n");
        return 1;
    }
    printf("Making %s\n", argv[1]);

    #define CRYPT_CALL(f) \
        do \
        { \
            if ((f) != CRYPT_OK) \
            { \
                fprintf(stderr, "Error calling %s\n", #f); \
                exit(EXIT_FAILURE); \
            } \
        } while (false)

    CRYPT_CALL(cryptInit());
    CRYPT_CALL(cryptCreateContext(&privKeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA));
    CRYPT_CALL(cryptSetAttributeString(privKeyContext, CRYPT_CTXINFO_LABEL, "label", 5));
    CRYPT_CALL(cryptSetAttribute(privKeyContext, CRYPT_CTXINFO_KEYSIZE, 1024 / 8));
    CRYPT_CALL(cryptGenerateKey(privKeyContext));
    CRYPT_CALL(cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
                    argv[1], CRYPT_KEYOPT_CREATE));
    CRYPT_CALL(cryptAddPrivateKey(cryptKeyset, privKeyContext, "password"));
    CRYPT_CALL(cryptKeysetClose(cryptKeyset));
    CRYPT_CALL(cryptDestroyContext(privKeyContext));
    CRYPT_CALL(cryptEnd());

    #undef CRYPT_CALL

    return 0;
}
