
/*
 * $Id: set_cert_ski.c 453 2007-07-25 15:30:40Z gardiner $ 
 */


#include "rpki/cms/roa_utils.h"
#include "rpki-asn1/manifest.h"
#include "util/hashutils.h"
#include "util/cryptlib_compat.h"
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

int main(
    int argc,
    char **argv)
{
    struct Certificate cert;

    Certificate(&cert, (ushort) 0);
    if (argc <= 1)
    {
        fprintf(stderr,
                "Usage: input certificate file name, [output file name]\n");
        exit(0);
    }
    if (get_casn_file(&cert.self, argv[1], 0) < 0)
    {
        fprintf(stderr, "error getting cert\n");
        return 0;
    }
    struct casn *pubkp =
        &cert.toBeSigned.subjectPublicKeyInfo.subjectPublicKey;
    uchar *keyp;
    int klth = readvsize_casn(pubkp, &keyp);
    uchar khash[24];
    int ansr = gen_hash(&keyp[1], klth - 1, khash, CRYPT_ALGO_SHA);
    if (ansr < 0)
    {
        fprintf(stderr, "Couldn't get CryptLib\n");
        return 0;
    }
    struct Extension *extp;
    for (extp =
         (struct Extension *)member_casn(&cert.toBeSigned.extensions.self, 0);
         extp; extp = (struct Extension *)next_of(&extp->self))
    {
        if (!diff_objid(&extp->extnID, id_subjectKeyIdentifier))
            break;
    }
    if (!extp)
        extp =
            (struct Extension *)member_casn(&cert.toBeSigned.extensions.self,
                                            num_items(&cert.toBeSigned.
                                                      extensions.self));
    write_objid(&extp->extnID, id_subjectKeyIdentifier);
    write_casn(&extp->extnValue.subjectKeyIdentifier, khash, ansr);
    char *c;
    if (put_casn_file(&cert.self, argv[2], 0) < 0)
        c = "error writing certificate\n";
    else
        c = "wrote certificate OK\n";
    fprintf(stderr, "%s", c);
    return 0;
}
