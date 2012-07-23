
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
#include <rpki-asn1/manifest.h>
#include <casn/casn.h>
#include <util/hashutils.h>
#include "create_object.h"

struct keyring {
    char filename[1024];        // expanded from 80 to 1024. it was cutting
                                // off filenames
    char label[10];
    char password[20];
} keyring;

static int setSignature(
    struct casn *tbhash,
    struct casn *newsignature)
{
    CRYPT_CONTEXT hashContext;
    CRYPT_CONTEXT sigKeyContext;
    CRYPT_KEYSET cryptKeyset;
    uchar hash[40];
    uchar *signature = NULL;
    int ansr = 0,
        signatureLength;
    char *msg = "";
    uchar *signstring = NULL;
    int sign_lth;

    if ((sign_lth = size_casn(tbhash)) < 0)
    {
        fprintf(stderr, "Error obtaining size of data to sign\n");
        return (1);
    }

    signstring = (uchar *) calloc(1, sign_lth);
    if (signstring == NULL)
    {
        fprintf(stderr, "Memory allocation Error signing certificate\n");
        return (1);
    }
    sign_lth = encode_casn(tbhash, signstring);
    if (sign_lth <= 0)
    {
        fprintf(stderr, "Error encoding certificate data\n");
        return (1);
    }

    memset(hash, 0, 40);
    if (cryptInit() != CRYPT_OK)
    {
        msg = "initializing cryptlib"
    }
    else if ((ansr =
         cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2)) != 0
        || (ansr =
            cryptCreateContext(&sigKeyContext, CRYPT_UNUSED,
                               CRYPT_ALGO_RSA)) != 0)
        msg = "creating context";
    else if ((ansr = cryptEncrypt(hashContext, signstring, sign_lth)) != 0 ||
             (ansr = cryptEncrypt(hashContext, signstring, 0)) != 0)
        msg = "hashing";
    else if ((ansr = cryptGetAttributeString(hashContext,
                                             CRYPT_CTXINFO_HASHVALUE, hash,
                                             &signatureLength)) != 0)
        msg = "getting attribute string";
    else if ((ansr =
              cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
                              keyring.filename, CRYPT_KEYOPT_READONLY)) != 0)
        msg = "opening key set";
    else if ((ansr = cryptGetPrivateKey(cryptKeyset, &sigKeyContext,
                                        CRYPT_KEYID_NAME, keyring.label,
                                        keyring.password)) != 0)
        msg = "getting key";
    else if ((ansr = cryptCreateSignature(NULL, 0, &signatureLength,
                                          sigKeyContext, hashContext)) != 0)
        msg = "signing";
    else
    {
        signature = (uchar *) calloc(1, signatureLength + 20);
        if ((ansr = cryptCreateSignature(signature, signatureLength + 20,
                                         &signatureLength, sigKeyContext,
                                         hashContext)) != 0)
            msg = "signing";
        else if ((ansr = cryptCheckSignature(signature, signatureLength,
                                             sigKeyContext, hashContext)) != 0)
            msg = "verifying";
    }
    cryptDestroyContext(hashContext);
    cryptDestroyContext(sigKeyContext);
    if (signstring)
        free(signstring);
    if (msg && *msg)
        fprintf(stderr, "Signature length = %d\n", signatureLength);
    signstring = NULL;
    if (ansr == 0)
    {
        struct SignerInfo siginfo;
        SignerInfo(&siginfo, (ushort) 0);
        if ((ansr = decode_casn(&siginfo.self, signature)) < 0)
            msg = "decoding signature";
        else if ((ansr = readvsize_casn(&siginfo.signature, &signstring)) < 0)
            msg = "reading signature";
        else
        {
            if ((ansr =
                 write_casn_bits(newsignature, signstring, ansr, 0)) < 0)
                msg = "writing signature";
            else
                ansr = 0;
        }
    }
    if (signstring != NULL)
        free(signstring);
    if (signature != NULL)
        free(signature);
    if (ansr)
    {
        fprintf(stderr, "Error %s object\n", msg);
        return (1);
    }
    return ansr;
}

/**
   sign_cert
   inputs:
       cert
       key file
   Returns
      0 = success
      <>0 error code
   Function
      Sign the ASN.1 encoded object using the private key from
      the file. Put the signature into the object.
*/

int sign_cert(
    struct Certificate *certp,
    char *keyname)
{
    struct AlgorithmIdentifier *algp,
       *tbsalgp;
    struct casn *casnp,
       *sigp,
       *selfp;
    int ret;


    selfp = &certp->self;
    casnp = &certp->toBeSigned.self;
    tbsalgp = &certp->toBeSigned.signature;
    sigp = &certp->signature;
    algp = &certp->algorithm;

    write_objid(&tbsalgp->algorithm, id_sha_256WithRSAEncryption);
    write_casn(&tbsalgp->parameters.rsadsi_SHA256_WithRSAEncryption,
               (uchar *) "", 0);
    strcpy(keyring.label, "label");
    strcpy(keyring.password, "password");
    strcpy(keyring.filename, keyname);
    if ((ret = setSignature(casnp, sigp)) != 0)
        return ret;

    write_objid(&algp->algorithm, id_sha_256WithRSAEncryption);
    write_casn(&algp->parameters.rsadsi_SHA256_WithRSAEncryption,
               (uchar *) "", 0);
    return 0;
}
