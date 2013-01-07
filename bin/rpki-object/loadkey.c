#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "util/cryptlib_compat.h"
#include <string.h>
#include <casn/casn.h>
#include "rpki-asn1/privkey.h"

/*
 * $Id$ 
 */

static void fatal(
    char *msg)
{
    if (msg && *msg)
        fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

uchar *setmember(
    struct casn * mem,
    uchar * bufp,
    int *sizep)
{
    if ((*sizep = read_casn(mem, bufp)) < 0)
        return (uchar *) 0;
    if (*bufp == 0)
    {
        bufp++;
        (*sizep)--;
    }
    return bufp;
}

int main(
    int argc,
    char **argv)
{
    CRYPT_CONTEXT privKeyContext;
    CRYPT_KEYSET cryptKeyset;
    CRYPT_PKCINFO_RSA *rsakey;
    struct PrivateKey privkey;
    uchar *c,
       *buf;
    int bsize,
        nsize;

    if (argc < 4)
        fprintf(stderr,
                "Need argv[1] for label, [2] for .req file, [3] for outfile\n");
    else
    {
        if (cryptInit() != CRYPT_OK)
        {
            fatal("Can't open Cryptlib");
        }

        if (cryptCreateContext(&privKeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA) != CRYPT_OK)
        {
            fatal("Can't create cryptlib private key context");
        }

        PrivateKey(&privkey, 0);
        if (get_casn_file(&privkey.self, argv[2], 0) < 0)
            fatal("Error getting key");

        bsize = size_casn(&privkey.n);
        buf = (uchar *) calloc(1, bsize);
        if (buf == NULL)
        {
            fatal("out of memory");
        }

        rsakey = malloc(sizeof(CRYPT_PKCINFO_RSA));
        if (rsakey == NULL)
        {
            fatal("out of memory");
        }

        cryptInitComponents(rsakey, CRYPT_KEYTYPE_PRIVATE);
        if (!(c = (uchar *) setmember(&privkey.n, buf, &nsize)))
            fatal("Error getting n");
        cryptSetComponent(rsakey->n, c, nsize * 8);
        if (!(c = (uchar *) setmember(&privkey.e, buf, &nsize)))
            fatal("Error getting e");
        cryptSetComponent(rsakey->e, c, nsize * 8);
        if (!(c = (uchar *) setmember(&privkey.d, buf, &nsize)))
            fatal("Error getting d");
        cryptSetComponent(rsakey->d, c, nsize * 8);
        if (!(c = (uchar *) setmember(&privkey.p, buf, &nsize)))
            fatal("Error getting p");
        cryptSetComponent(rsakey->p, c, nsize * 8);
        if (!(c = (uchar *) setmember(&privkey.q, buf, &nsize)))
            fatal("Error getting q");
        cryptSetComponent(rsakey->q, c, nsize * 8);
        if (!(c = (uchar *) setmember(&privkey.u, buf, &nsize)))
            fatal("Error getting u");
        cryptSetComponent(rsakey->u, c, nsize * 8);
        if (!(c = (uchar *) setmember(&privkey.e1, buf, &nsize)))
            fatal("Error getting e1");
        cryptSetComponent(rsakey->e1, c, nsize * 8);
        if (!(c = (uchar *) setmember(&privkey.e2, buf, &nsize)))
            fatal("Error getting e2");
        cryptSetComponent(rsakey->e2, c, nsize * 8);

        if (cryptSetAttributeString(privKeyContext, CRYPT_CTXINFO_LABEL,
                                    argv[1], strlen(argv[1])) != CRYPT_OK)
        {
            fatal("Can't set label attribute string");
        }

        if (cryptSetAttributeString(privKeyContext,
                                    CRYPT_CTXINFO_KEY_COMPONENTS, rsakey,
                                    sizeof(CRYPT_PKCINFO_RSA)) != CRYPT_OK)
        {
            fatal("Can't set key components attribute string");
        }

        if (cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
                            argv[3], CRYPT_KEYOPT_CREATE) != CRYPT_OK)
        {
            fatal("Can't open keyset");
        }

        if (cryptAddPrivateKey(cryptKeyset, privKeyContext, "password") != CRYPT_OK)
        {
            fatal("Can't add private key to keyset");
        }

        if (cryptDestroyContext(privKeyContext) != CRYPT_OK)
        {
            fatal("Can't destroy private key context");
        }

        cryptEnd();
    }
    return 0;
}
