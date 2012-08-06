#include "util/cryptlib_compat.h"
#include "util/hashutils.h"
#include "util/logging.h"
#include "rpki-asn1/roa.h"
#include "rpki-object/certificate.h"


struct Extension *find_extension(
    struct Extensions *extsp,
    const char *oid,
    bool create)
{
    struct Extension *extp;
    for (extp = (struct Extension *)member_casn(&extsp->self, 0);
         extp && diff_objid(&extp->extnID, oid);
         extp = (struct Extension *)next_of(&extp->self));
    if (!extp && create)
    {
        int num = num_items(&extsp->self);
        extp = (struct Extension *)inject_casn(&extsp->self, num);
        if (extp)
            write_objid(&extp->extnID, oid);
    }
    return extp;
}

struct Extension *make_extension(
    struct Extensions *extsp,
    const char *oid)
{
    struct Extension *extp = find_extension(extsp, oid, false);
    if (extp == NULL)
    {
        extp = (struct Extension *)inject_casn(&extsp->self,
                                               num_items(&extsp->self));
        if (extp == NULL)
        {
            return NULL;
        }
    }
    else
    {
        clear_casn(&extp->self);
    }

    write_objid(&extp->extnID, oid);

    return extp;
}

bool check_signature(
    struct casn *locertp,
    struct Certificate *hicertp,
    struct casn *sigp)
{
    CRYPT_CONTEXT pubkeyContext,
        hashContext;
    bool pubkeyContextInitialized = false;
    bool hashContextInitialized = false;
    CRYPT_PKCINFO_RSA rsakey;
    // CRYPT_KEYSET cryptKeyset;
    struct RSAPubKey rsapubkey;
    bool rsapubkeyInitialized = false;
    struct SignerInfo sigInfo;
    bool sigInfoInitialized = false;
    int bsize,
        sidsize;
    uchar *c,
       *buf = NULL,
        hash[40],
        sid[40];
    bool ret = true;

    // get SID and generate the sha-1 hash
    // (needed for cryptlib; see below)
    memset(sid, 0, 40);
    bsize = size_casn(&hicertp->toBeSigned.subjectPublicKeyInfo.self);
    if (bsize < 0)
    {
        LOG(LOG_ERR, "low cert size");
        ret = false;
        goto done;
    }
    buf = (uchar *) calloc(1, bsize);
    encode_casn(&hicertp->toBeSigned.subjectPublicKeyInfo.self, buf);
    sidsize = gen_hash(buf, bsize, sid, CRYPT_ALGO_SHA);
    if (sidsize < 0)
    {
        LOG(LOG_ERR, "gen_hash failed");
        ret = false;
        goto done;
    }
    free(buf);
    buf = NULL;

    // generate the sha256 hash of the signed attributes. We don't call
    // gen_hash because we need the hashContext for later use (below).
    memset(hash, 0, 40);
    bsize = size_casn(locertp);
    if (bsize < 0)
    {
        LOG(LOG_ERR, "error sizing toBeSigned");
        ret = false;
        goto done;
    }
    buf = (uchar *) calloc(1, bsize);
    encode_casn(locertp, buf);

    // (re)init the crypt library
    if (cryptInit() != CRYPT_OK)
    {
        LOG(LOG_ERR, "error initializing cryptlib");
        ret = false;
        goto done;
    }
    cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2);
    hashContextInitialized = true;
    cryptEncrypt(hashContext, buf, bsize);
    cryptEncrypt(hashContext, buf, 0);
    cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ret);
    free(buf);

    // get the public key from the certificate and decode it into an RSAPubKey
    readvsize_casn(&hicertp->toBeSigned.subjectPublicKeyInfo.subjectPublicKey,
                   &c);
    RSAPubKey(&rsapubkey, 0);
    rsapubkeyInitialized = true;
    decode_casn(&rsapubkey.self, &c[1]);        // skip 1st byte (tag?) in BIT 
                                                // STRING
    free(c);

    // set up the key by reading the modulus and exponent
    cryptCreateContext(&pubkeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA);
    pubkeyContextInitialized = true;
    cryptSetAttributeString(pubkeyContext, CRYPT_CTXINFO_LABEL, "label", 5);
    cryptInitComponents(&rsakey, CRYPT_KEYTYPE_PUBLIC);

    // read the modulus from rsapubkey
    bsize = readvsize_casn(&rsapubkey.modulus, &buf);
    c = buf;
    // if the first byte is a zero, skip it
    if (!*buf)
    {
        c++;
        bsize--;
    }
    cryptSetComponent((&rsakey)->n, c, bsize * 8);
    free(buf);
    buf = NULL;

    // read the exponent from the rsapubkey
    bsize = readvsize_casn(&rsapubkey.exponent, &buf);
    cryptSetComponent((&rsakey)->e, buf, bsize * 8);
    free(buf);
    buf = NULL;

    // set the modulus and exponent on the key
    cryptSetAttributeString(pubkeyContext, CRYPT_CTXINFO_KEY_COMPONENTS,
                            &rsakey, sizeof(CRYPT_PKCINFO_RSA));
    // all done with this now, free the storage
    cryptDestroyComponents(&rsakey);

    // make the structure cryptlib likes.
    // we discovered through detective work that cryptlib wants the
    // signature's SID field to be the sha-1 hash of the SID.
    SignerInfo(&sigInfo, (ushort) 0);   /* init sigInfo */
    sigInfoInitialized = true;
    write_casn_num(&sigInfo.version.self, 3);
    // copy_casn(&sigInfo.version.self, &sigInfop->version.self); /* copy over 
    // */
    // copy_casn(&sigInfo.sid.self, &sigInfop->sid.self); /* copy over */
    write_casn(&sigInfo.sid.subjectKeyIdentifier, sid, sidsize);        /* sid 
                                                                         * hash */

    // copy over digest algorithm, signature algorithm, signature
    write_objid(&sigInfo.digestAlgorithm.algorithm, id_sha256);
    write_casn(&sigInfo.digestAlgorithm.parameters.sha256, (uchar *) "", 0);
    write_objid(&sigInfo.signatureAlgorithm.algorithm,
                id_rsadsi_rsaEncryption);
    write_casn(&sigInfo.signatureAlgorithm.parameters.rsadsi_rsaEncryption,
               (uchar *) "", 0);
    uchar *sig;
    int siglth = readvsize_casn(sigp, &sig);
    write_casn(&sigInfo.signature, &sig[1], siglth - 1);
    free(sig);
    sig = NULL;

    // now encode as asn1, and check the signature
    bsize = size_casn(&sigInfo.self);
    buf = (uchar *) calloc(1, bsize);
    encode_casn(&sigInfo.self, buf);
    if (cryptCheckSignature(buf, bsize, pubkeyContext, hashContext) != CRYPT_OK)
    {
        LOG(LOG_DEBUG, "error checking signature");
        ret = false;
        goto done;
    }

done:
    free(buf);

    if (pubkeyContextInitialized)
        cryptDestroyContext(pubkeyContext);

    if (hashContextInitialized)
        cryptDestroyContext(hashContext);

    if (rsapubkeyInitialized)
        delete_casn(&rsapubkey.self);

    if (sigInfoInitialized)
        delete_casn(&sigInfo.self);

    return ret;
}

bool check_cert_signature(
    struct Certificate *locertp,
    struct Certificate *hicertp)
{
    return check_signature(&locertp->toBeSigned.self, hicertp,
                           &locertp->signature);
}

int writeHashedPublicKey(
    struct casn *valuep,
    struct casn *keyp,
    bool bad)
{
    uchar *bitval;
    int siz = readvsize_casn(keyp, &bitval);
    uchar hashbuf[24];
    siz = gen_hash(&bitval[1], siz - 1, hashbuf, CRYPT_ALGO_SHA);
    free(bitval);
    if (bad)
        hashbuf[0]++;
    write_casn(valuep, hashbuf, siz);
    return siz;
}
