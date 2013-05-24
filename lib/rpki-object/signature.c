#include "util/cryptlib_compat.h"
#include "util/logging.h"
#include "rpki-asn1/cms.h"

#include "signature.h"

bool set_signature(
    struct casn *content,
    struct casn *signature,
    const char *keyfile,
    const char *label,
    const char *password,
    bool bad)
{
    CRYPT_CONTEXT hashContext;
    CRYPT_CONTEXT sigKeyContext;
    CRYPT_KEYSET cryptKeyset;
    uchar hash[40];
    uchar *signatureData = NULL;
    int signatureLength;
    uchar *signstring = NULL;
    int sign_lth;
    bool ret = true;

    if ((sign_lth = size_casn(content)) < 0)
    {
        LOG(LOG_ERR, "can't size the content");
        return false;
    }

    signstring = (uchar *) calloc(1, sign_lth);
    if (signstring == NULL)
    {
        LOG(LOG_ERR, "out of memory");
        return false;
    }

    sign_lth = encode_casn(content, signstring);

    memset(hash, 0, 40);

    if (cryptInit() != CRYPT_OK)
    {
        LOG(LOG_ERR, "can't initialize cryptlib");
        free(signstring);
        return false;
    }

    if (cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2) != 0)
    {
        LOG(LOG_ERR, "can't create hash context");
        free(signstring);
        return false;
    }

    if (cryptCreateContext(&sigKeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA) != 0)
    {
        LOG(LOG_ERR, "can't create sig key context");
        cryptDestroyContext(hashContext);
        free(signstring);
        return false;
    }
    
    if (cryptEncrypt(hashContext, signstring, sign_lth) != 0 ||
        cryptEncrypt(hashContext, signstring, 0) != 0)
    {
        LOG(LOG_ERR, "can't hash content");
        ret = false;
        goto done;
    }

    if (cryptGetAttributeString(hashContext,
                                CRYPT_CTXINFO_HASHVALUE, hash,
                                &signatureLength) != 0)
    {
        LOG(LOG_ERR, "error getting attribute string");
        ret = false;
        goto done;
    }

    if (cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED,
                        CRYPT_KEYSET_FILE, keyfile,
                        CRYPT_KEYOPT_READONLY) != 0)
    {
        LOG(LOG_ERR, "can't open key set");
        ret = false;
        goto done;
    }

    if (cryptGetPrivateKey(cryptKeyset, &sigKeyContext,
                           CRYPT_KEYID_NAME, label,
                           password) != 0)
    {
        LOG(LOG_ERR, "can't get key");
        ret = false;
        goto done;
    }

    if (cryptCreateSignature(NULL, 0, &signatureLength,
                             sigKeyContext, hashContext) != 0)
    {
        LOG(LOG_ERR, "can't determine size of signature");
        ret = false;
        goto done;
    }

    signatureData = (uchar *) calloc(1, signatureLength + 20);
    if (signatureData == NULL)
    {
        LOG(LOG_ERR, "out of memory");
        ret = false;
        goto done;
    }
    
    if (cryptCreateSignature(signatureData, signatureLength + 20,
                             &signatureLength, sigKeyContext,
                             hashContext) != 0)
    {
        LOG(LOG_ERR, "can't sign hash");
        ret = false;
        goto done;
    }
    
    if (cryptCheckSignature(signatureData, signatureLength,
                            sigKeyContext, hashContext) != 0)
    {
        LOG(LOG_ERR, "signature verification failed");
        ret = false;
        goto done;
    }

    free(signstring);
    signstring = NULL;

    struct SignerInfo siginfo;
    SignerInfo(&siginfo, (ushort) 0);

    if (decode_casn(&siginfo.self, signatureData) < 0)
    {
        LOG(LOG_ERR, "can't decode signature");
        ret = false;
        goto done;
    }

    sign_lth = readvsize_casn(&siginfo.signature, &signstring);
    if (sign_lth < 0)
    {
        LOG(LOG_ERR, "can't read signature from SignerInfo");
        ret = false;
        goto done;
    }

    if (bad)
    {
        signstring[0]++;
    }

    if (write_casn_bits(signature, signstring, sign_lth, 0) < 0)
    {
        LOG(LOG_ERR, "can't write signature");
        ret = false;
        goto done;
    }

done:
    cryptDestroyContext(hashContext);
    cryptDestroyContext(sigKeyContext);
    free(signstring);
    free(signatureData);
    return ret;
}
