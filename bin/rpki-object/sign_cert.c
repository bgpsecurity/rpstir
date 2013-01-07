/*
 * $Id: sign_cert.c c 506 2008-06-03 21:20:05Z gardiner $ 
 */


#include <stdio.h>
#include <util/cryptlib_compat.h>
#include <rpki-asn1/keyfile.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <rpki-asn1/certificate.h>
#include <rpki-asn1/crlv2.h>
#include <rpki-asn1/roa.h>
#include <casn/casn.h>
#include <rpki-asn1/blob.h>
#include <rpki-object/signature.h>
#include <util/logging.h>

char *msgs[] = {
    "Finished %s OK\n",
    "Error in %s\n",
    "Usage: TBS filename, Key filename [1 to adjust dates | 2 to keep tbs alg]\n",
    "Couldn't open %s\n",
    "Error getting memory\n",
};

static void adjust_time(
    struct casn *fromp,
    struct casn *tillp)
{
    int64_t begt,
        till;
    read_casn_time(fromp, &begt);
    read_casn_time(tillp, &till);
    till -= begt;
    begt = time(NULL);
    till += begt;
    write_casn_time(fromp, begt);
    write_casn_time(tillp, till);
}

static void fatal(
    int err,
    char *paramp)
{
    fprintf(stderr, msgs[err], paramp);
    if (err)
        exit(err);
}


int main(
    int argc,
    char **argv)
{
    /*
     * Args are: file TBS, keyfile, [update] 
     */
    struct Certificate cert;
    Certificate(&cert, (ushort) 0);
    struct CertificateRevocationList crl;
    CertificateRevocationList(&crl, (ushort) 0);
    struct Blob blob;
    Blob(&blob, (ushort) 0);
    struct AlgorithmIdentifier *algp,
       *tbsalgp;
    struct casn *casnp,
       *sigp,
       *selfp;
    const char *keyfile = NULL;

    OPEN_LOG("sign_cert", LOG_USER);

    if (argc < 3)
        fatal(2, (char *)0);
    char *sfx = strrchr(argv[1], (int)'.');
    keyfile = argv[2];
    if (!strcmp(sfx, ".cer"))
    {
        selfp = &cert.self;
        casnp = &cert.toBeSigned.self;
        tbsalgp = &cert.toBeSigned.signature;
        sigp = &cert.signature;
        algp = &cert.algorithm;
    }
    else if (!strcmp(sfx, ".crl"))
    {
        selfp = &crl.self;
        casnp = &crl.toBeSigned.self;
        tbsalgp = &crl.toBeSigned.signature;
        sigp = &crl.signature;
        algp = &crl.algorithm;
    }
    else if (!strcmp(sfx, ".blb"))
    {
        selfp = &blob.self;
        casnp = &blob.toBeSigned;
        tbsalgp = NULL;
        sigp = &blob.signature;
        algp = &blob.algorithm;
    }
    if (get_casn_file(selfp, argv[1], 0) < 0)
        fatal(3, argv[1]);
    if (argv[3] && (*argv[3] & 1))
    {
        if (!strcmp(sfx, ".cer"))
            adjust_time(&cert.toBeSigned.validity.notBefore.utcTime,
                        &cert.toBeSigned.validity.notAfter.utcTime);
        else if (!strcmp(sfx, ".crl"))
            adjust_time((struct casn *)&crl.toBeSigned.lastUpdate,
                        (struct casn *)&crl.toBeSigned.nextUpdate);
    }
    if (tbsalgp && (!argv[3] || !(*argv[3] & 2)))
    {
        write_objid(&tbsalgp->algorithm, id_sha_256WithRSAEncryption);
        write_casn(&tbsalgp->parameters.rsadsi_SHA256_WithRSAEncryption,
                   (uchar *) "", 0);
    }
    if (!set_signature(casnp, sigp, keyfile, "label", "password", false))
    {
        fatal(1, "set_signature()");
    }
    if (!argv[3] || !(*argv[3] & 4))
    {
        write_objid(&algp->algorithm, id_sha_256WithRSAEncryption);
        write_casn(&algp->parameters.rsadsi_SHA256_WithRSAEncryption,
                   (uchar *) "", 0);
    }
    put_casn_file(selfp, argv[1], 0);
    fatal(0, argv[1]);
    return 0;
}
