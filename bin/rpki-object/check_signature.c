#include "util/logging.h"
#include "rpki/cms/roa_utils.h"
#include "rpki-asn1/crlv2.h"
#include "util/cryptlib_compat.h"
#include "rpki-asn1/blob.h"
#include "util/hashutils.h"
#include "rpki-object/certificate.h"

#define MSG_USAGE "Usage: signed cert or CRL, signer's cert"
#define MSG_GET "Can't get file %s"
#define MSG_SIG_CHECK "Signature checking error in %s"
#define MSG_TYPE "Invalid type %s"
#define MSG_ALG "Invalid algorithm %s"

int main(
    int argc,
    char **argv)
{
    OPEN_LOG("check_signature", LOG_USER);
    if (argc != 3)
        FATAL(MSG_USAGE);
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
        FATAL(MSG_TYPE, argv[1]);
    if (ansr < 0)
        FATAL(MSG_GET, argv[1]);
    if (get_casn_file(&hicert.self, argv[2], 0) < 0)
        FATAL(MSG_GET, argv[2]);
    /** @bug error code ignored without explanation */
    if (diff_objid(&algp->algorithm, id_sha_256WithRSAEncryption))
    {
        char oidbuf[80];
        /** @bug error code ignored without explanation */
        read_objid(&algp->algorithm, oidbuf);
        FATAL(MSG_ALG, oidbuf);
    }
    if (!check_signature(tbsp, &hicert, sigp))
        fprintf(stderr, "Signature failed\n");
    fprintf(stderr, "Signature succeeded\n");
    return 0;
}
