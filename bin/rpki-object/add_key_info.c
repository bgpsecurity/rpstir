#include <stdio.h>
#include <util/cryptlib_compat.h>
#include <rpki-asn1/keyfile.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <rpki-object/certificate.h>
#include <rpki-asn1/crlv2.h>
#include <casn/casn.h>
#include <util/hashutils.h>
#include "util/logging.h"

#define MSG_OK "Finished OK"
#define MSG_OPEN "Couldn't open %s"
#define MSG_FIND_SKI "Couldn't find %s subject key identifier"
#define MSG_USAGE "Usage: file names for certificate/CRL, subject key, [authority certificate]"
#define MSG_DIFFER "Subject and issuer differ in %s; need authority certificate"
#define MSG_GET "Couldn't get %s"
#define MSG_UNK_EXT "Unknown file extension for %s"


static struct Extension *find_CRLextension(
    struct CrlExtensions *extsp,
    char *idp,
    int creat)
{
    struct Extension *extp;
    /** @bug error code ignored without explanation */
    for (extp = (struct Extension *)member_casn(&extsp->self, 0);
         /** @bug error code ignored without explanation */
         extp && diff_objid(&extp->extnID, idp);
         /** @bug error code ignored without explanation */
         extp = (struct Extension *)next_of(&extp->self));
    if (!extp && creat)
    {
        /** @bug error code ignored without explanation */
        int num = num_items(&extsp->self);
        /** @bug error code ignored without explanation */
        extp = (struct Extension *)inject_casn(&extsp->self, num);
        if (extp)
            /** @bug error code ignored without explanation */
            write_objid(&extp->extnID, idp);
    }
    return extp;
}

int main(
    int argc,
    char **argv)
{
    struct Certificate scert,
        acert;
    Certificate(&scert, (ushort) 0);
    Certificate(&acert, (ushort) 0);
    struct CertificateRevocationList crl;
    struct Keyfile keyfile;
    Keyfile(&keyfile, (ushort) 0);
    if (argc < 3)
        FATAL(MSG_USAGE);
    if (get_casn_file(&keyfile.self, argv[2], 0) < 0)
        FATAL(MSG_OPEN, argv[2]);
    uchar *keyp;
    int ksiz = readvsize_casn(&keyfile.content.bbb.ggg.iii.nnn.ooo.ppp.key,
                              &keyp);
    uchar hashbuf[40];
    int hsize = gen_hash(&keyp[1], ksiz - 1, hashbuf, CRYPT_ALGO_SHA1);
    if (hsize < 0)
        FATAL(MSG_GET, "hash");
    char *buf,
       *c = strrchr(argv[1], (int)'.');
    int siz;
    if (!c)
        FATAL(MSG_OPEN, argv[1]);
    if (!strcmp(c, ".crl"))
    {
        CertificateRevocationList(&crl, (ushort) 0);
        struct CRLExtension *aextp;
        if (get_casn_file(&crl.self, argv[1], 0) < 0)
            FATAL(MSG_OPEN, argv[1]);
        if (!
            (aextp =
             (struct CRLExtension *)find_CRLextension(&crl.toBeSigned.
                                                      extensions, id_authKeyId,
                                                      0)))
            FATAL(MSG_FIND_SKI, "authority");
        write_casn(&aextp->extnValue.authKeyId.keyIdentifier, hashbuf, hsize);
        put_casn_file(&crl.self, argv[1], 0);
        siz = dump_size(&crl.self);
        buf = (char *)calloc(1, siz + 2);
        dump_casn(&crl.self, buf);
    }
    else if (!strcmp(c, ".cer"))
    {
        struct Extension *aextp,
           *sextp;
        if (get_casn_file(&scert.self, argv[1], 0) < 0)
            FATAL(MSG_OPEN, argv[1]);
        struct Extensions *extsp = &scert.toBeSigned.extensions;
        if (!(sextp = find_extension(extsp, id_subjectKeyIdentifier, 1)))
            FATAL(MSG_FIND_SKI, "subject's");
        if (!(aextp = find_extension(extsp, id_authKeyId, 0)) && argc > 3)
            FATAL(MSG_FIND_SKI, "authority");
        write_casn(&sextp->extnValue.subjectKeyIdentifier, hashbuf, hsize);
        if (diff_casn
            (&scert.toBeSigned.subject.self, &scert.toBeSigned.issuer.self))
        {
            if (argc < 4)
                FATAL(MSG_DIFFER, argv[1]);
            if (get_casn_file(&acert.self, argv[3], 0) < 0)
                FATAL(MSG_OPEN, argv[3]);
            if (!(sextp = find_extension(&acert.toBeSigned.extensions,
                                         id_subjectKeyIdentifier, 0)))
                FATAL(MSG_FIND_SKI, "authority's");
            hsize = read_casn(&sextp->extnValue.subjectKeyIdentifier, hashbuf);
        }
        if (aextp)
            write_casn(&aextp->extnValue.authKeyId.keyIdentifier, hashbuf,
                       hsize);

        write_casn(&scert.toBeSigned.subjectPublicKeyInfo.subjectPublicKey,
                   keyp, ksiz);
        put_casn_file(&scert.self, argv[1], 0);
        siz = dump_size(&scert.self);
        buf = (char *)calloc(1, siz + 2);
        dump_casn(&scert.self, buf);
    }
    else
    {
        FATAL(MSG_UNK_EXT, argv[1]);
    }
    char fname[80];
    strcat(strcpy(fname, argv[1]), ".raw");
    int fd = creat(fname, 0777);
    if (write(fd, buf, siz) != siz)
        abort();
    return 0;
}
