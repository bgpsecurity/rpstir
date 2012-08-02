#include "util/cryptlib_compat.h"
#include "rpki-asn1/roa.h"

#include "crl.h"


const char *signCRL(
    struct CertificateRevocationList *crlp,
    const char *keyfile)
{
    CRYPT_CONTEXT hashContext;
    CRYPT_CONTEXT sigKeyContext;
    CRYPT_KEYSET cryptKeyset;
    uchar hash[40];
    uchar *signature = NULL;
    int ansr = 0,
        signatureLength;
    const char *msg = NULL;
    uchar *signstring = NULL;
    int sign_lth;

    sign_lth = size_casn(&crlp->toBeSigned.self);
    signstring = (uchar *) calloc(1, sign_lth);
    sign_lth = encode_casn(&crlp->toBeSigned.self, signstring);
    memset(hash, 0, 40);
    cryptInit();
    if ((ansr =
         cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2)) != 0
        || (ansr =
            cryptCreateContext(&sigKeyContext, CRYPT_UNUSED,
                               CRYPT_ALGO_RSA)) != 0)
        msg = "creating context";
    else if ((ansr = cryptEncrypt(hashContext, signstring, sign_lth)) != 0 ||
             (ansr = cryptEncrypt(hashContext, signstring, 0)) != 0)
        msg = "hashing";
    else if ((ansr =
              cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE,
                                      hash, &signatureLength)) != 0)
        msg = "getting attribute string";
    else if ((ansr =
              cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
                              keyfile, CRYPT_KEYOPT_READONLY)) != 0)
        msg = "opening key set";
    else if ((ansr =
              cryptGetPrivateKey(cryptKeyset, &sigKeyContext, CRYPT_KEYID_NAME,
                                 "label", "password")) != 0)
        msg = "getting key";
    else if ((ansr =
              cryptCreateSignature(NULL, 0, &signatureLength, sigKeyContext,
                                   hashContext)) != 0)
        msg = "signing";
    else
    {
        signature = (uchar *) calloc(1, signatureLength + 20);
        if ((ansr = cryptCreateSignature(signature, signatureLength + 20,
                                         &signatureLength, sigKeyContext,
                                         hashContext)) != 0)
            msg = "signing";
        else if ((ansr =
                  cryptCheckSignature(signature, signatureLength,
                                      sigKeyContext, hashContext)) != 0)
            msg = "verifying";
    }

    cryptDestroyContext(hashContext);
    cryptDestroyContext(sigKeyContext);
    cryptEnd();
    if (signstring)
        free(signstring);
    signstring = NULL;
    if (ansr == 0)
    {
        struct SignerInfo siginfo;
        SignerInfo(&siginfo, (ushort) 0);
        if ((ansr = decode_casn(&siginfo.self, signature)) < 0)
            msg = "decoding signature";
        else if ((ansr = readvsize_casn(&siginfo.signature, &signstring)) < 0)
            msg = "reading signature";
        else if ((ansr =
                  write_casn_bits(&crlp->signature, signstring, ansr, 0)) < 0)
            msg = "writing signature";
        else
            ansr = 0;
    }
    if (signstring != NULL)
        free(signstring);
    if (signature != NULL)
        free(signature);
    return msg;
}
