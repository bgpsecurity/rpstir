/*
 * $Id: check_signature.c c 506 2008-06-03 21:20:05Z gardiner $ 
 */

#include "util/logging.h"
#include "rpki/cms/roa_utils.h"
#include "rpki-asn1/crlv2.h"
#include "util/cryptlib_compat.h"
#include "rpki-asn1/blob.h"
#include "util/hashutils.h"
#include "rpki-object/certificate.h"

char *msgs[] = {
    "Signature %s\n",
    "Usage: signed cert or CRL, signer's cert\n",
    "Can't get file %s\n",
    "Signature checking error in %s\n",
    "Invalid type %s\n",
    "Invalid algorithm %s\n",
};

static void fatal(
    int err,
    char *param)
{
    fprintf(stderr, msgs[err], param);
    if (err)
        exit(err);
}

int main(
    int argc,
    char **argv)
{
    OPEN_LOG("check_signature", LOG_USER);
    if (argc != 3)
        fatal(1, (char *)0);
    struct Certificate locert,
        hicert;
    struct CertificateRevocationList crl;
    Certificate(&locert, (ushort) 0);
    Certificate(&hicert, (ushort) 0);
    CertificateRevocationList(&crl, (ushort) 0);
    struct Blob blob;
    Blob(&blob, (ushort) 0);
    struct casn *tbsp,
       *sigp;
    struct AlgorithmIdentifier *algp;
    char *sfx = strchr(argv[1], (int)'.');
    int ansr;
    if (!strcmp(sfx, ".cer"))
    {
        tbsp = &locert.toBeSigned.self;
        algp = &locert.algorithm;
        sigp = &locert.signature;
        ansr = get_casn_file(&locert.self, argv[1], 0);
    }
    else if (!strcmp(sfx, ".crl"))
    {
        tbsp = &crl.toBeSigned.self;
        algp = &crl.algorithm;
        sigp = &crl.signature;
        ansr = get_casn_file(&crl.self, argv[1], 0);
    }
    else if (!strcmp(sfx, ".blb"))
    {
        tbsp = &blob.toBeSigned;
        algp = &blob.algorithm;
        sigp = &blob.signature;
        ansr = get_casn_file(&blob.self, argv[1], 0);
    }
    else
        fatal(4, argv[1]);
    if (ansr < 0)
        fatal(2, argv[1]);
    if (get_casn_file(&hicert.self, argv[2], 0) < 0)
        fatal(2, argv[2]);
    if (diff_objid(&algp->algorithm, id_sha_256WithRSAEncryption))
    {
        char oidbuf[80];
        read_objid(&algp->algorithm, oidbuf);
        fatal(5, oidbuf);
    }
    if (!check_signature(tbsp, &hicert, sigp))
        fatal(0, "failed");
    fatal(0, "succeeded");
    return 0;
}
