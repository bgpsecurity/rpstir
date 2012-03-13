#include <stdio.h>
#include <cryptlib.h>
#include <keyfile.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <certificate.h>
#include <roa.h>
#include <casn.h>

char *msgs [] = {
  "Finished OK\n",
  "Couldn't get %s\n",
  "Error inserting %s\n",   // 2
  "EEcert has no key identifier\n", 
  "Error signing in %s\n",
  }; 

static void fatal(int err, char *paramp)
  {
  fprintf(stderr, msgs[err], paramp);
  exit(err);
  }

struct keyring
  {
  char filename[80];
  char label[20];
  char password[20];
  };

static struct keyring keyring;
 
static struct Extension *find_extension(struct Certificate *certp, char *idp)
  {
  struct Extension *extp;
  for (extp = (struct Extension *)member_casn(
    &certp->toBeSigned.extensions.self, 0);
    extp && diff_objid(&extp->extnID, idp);
    extp = (struct Extension *)next_of(&extp->self));
  return extp;
  }

int CryptInitState;

static int gen_hash(uchar *inbufp, int bsize, uchar *outbufp, 
    CRYPT_ALGO_TYPE alg)
  { 
  CRYPT_CONTEXT hashContext;
  uchar hash[40];
  int ansr = -1;

  if (alg != CRYPT_ALGO_SHA && alg != CRYPT_ALGO_SHA2) return -1;
  memset(hash, 0, 40);
  if (!CryptInitState)
    {
    if (cryptInit() != CRYPT_OK) fatal(1, "CryptInit");
    CryptInitState = 1;
    }

  if (cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2) < 0)
    fatal(2, "cryptContext"); 
  cryptEncrypt(hashContext, inbufp, bsize);
  cryptEncrypt(hashContext, inbufp, 0);
  cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ansr);
  cryptDestroyContext(hashContext);
  if (ansr > 0) memcpy(outbufp, hash, ansr);
  return ansr;
  }

// return a printable message indicating the error (if any) or NULL if not
//
static char *signCMS(struct CMSBlob* roa, char *keyfilename, int bad)
  {
  CRYPT_CONTEXT sigKeyContext;
  CRYPT_KEYSET cryptKeyset;
  CRYPT_CONTEXT hashContext;
  int signatureLength, tbs_lth;
  char *msg = (char *)0;
  uchar *tbsp, *signature = NULL, hash[40];
  struct SignerInfo *signerInfop = (struct SignerInfo *)member_casn(
      &roa->content.signedData.signerInfos.self, 0);

  if (!CryptInitState)
    {
    if (cryptInit() != CRYPT_OK) fatal(1, "CryptInit");
    CryptInitState = 1;
    }
    // get the size of signed attributes and allocate space for them
  if ((tbs_lth = size_casn(&signerInfop->signedAttrs.self)) < 0) 
    msg = "sizing SignerInfo";
  else
    {
    tbsp = (uchar *)calloc(1, tbs_lth);
    tbs_lth = encode_casn(&signerInfop->signedAttrs.self, tbsp);
    *tbsp = ASN_SET;

    if (cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2) <0)
      msg = "creating hash context";
    else if (cryptEncrypt(hashContext, tbsp, tbs_lth) < 0 ||
      cryptEncrypt(hashContext, tbsp, 0) < 0) msg = "hasingg attrs";
    else if (cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE,
      hash, &signatureLength) < 0) msg = "getting attr hash";
    // get the key and sign it
    else if(cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, 
      keyfilename, CRYPT_KEYOPT_READONLY) < 0) msg =  "opening key set";
    else if(cryptCreateContext(&sigKeyContext, CRYPT_UNUSED, 
      CRYPT_ALGO_RSA) < 0) msg = "creating RSA context";
    else if(cryptGetPrivateKey(cryptKeyset, &sigKeyContext, CRYPT_KEYID_NAME, 
      keyring.label, keyring.password) < 0) msg = "getting key";
    else if(cryptCreateSignature(NULL, 0, &signatureLength, sigKeyContext, 
      hashContext) < 0) msg = "signing";
    else
      {
      // check the signature to make sure it's right
      signature = (uchar *)calloc(1, signatureLength +20);
      //  second parameter is signatureMaxLength, so we allow a little more
      if (cryptCreateSignature(signature, signatureLength+20, &signatureLength, 
        sigKeyContext, hashContext) < 0) msg = "signing";
      // verify that the signature is right
      else if (cryptCheckSignature(signature, signatureLength, sigKeyContext, 
        hashContext) < 0) msg = "verifying";
      }
    }

  cryptDestroyContext(hashContext);
  cryptDestroyContext(sigKeyContext);

  if (!msg) 
    {
    struct SignerInfo sigInfo;
    SignerInfo(&sigInfo, (ushort)0); 
    decode_casn(&sigInfo.self, signature);
    // copy the signature into the object
    copy_casn(&signerInfop->signature, &sigInfo.signature);
    delete_casn(&sigInfo.self);
    }
  else fprintf(stderr, "Signing failed when %s\n", msg);
  // all done with it now
  if (signature) free(signature);
  return NULL;
  }

int main(int argc, char **argv)
  {
  struct CMSBlob roa;
  CMSBlob(&roa, (ushort)0);
  if (argc < 4 || argc > 5 )
    {
      fprintf(stderr, "Usage: %s EEcert CMSfile EEkeyfile [outfile]\n",
         argv[0]);
      fprintf(stderr, "If the environment variable RPKI_NO_SIGNING_TIME is set,\n");
      fprintf(stderr, "the signing time won't be set.\n");
      return -1;
    }
  strcpy(keyring.label, "label");
  strcpy(keyring.password, "password");
  struct Certificate EEcert;
  Certificate(&EEcert, (ushort)0);
        // get the EE cert
  if (get_casn_file(&EEcert.self, argv[1], 0) < 0) 
    fatal(1, "EE certificate");
        // get the CMS object
  if (get_casn_file(&roa.self, argv[2], 0) < 0) 
    fatal(1, "CMS file");
  struct Extension *sextp;
      // get EE's Auth Key ID
  if (!(sextp = find_extension(&EEcert, id_authKeyId))) 
      fatal(3, "key identifier");
     // add cert to CMS object 
  struct BlobSignedData *signedDatap = &roa.content.signedData;
  struct Certificate *certp;
  clear_casn(&signedDatap->certificates.self);
  certp = (struct Certificate *)inject_casn(&signedDatap->certificates.self, 0);
  if (!certp) fatal(2, "EE certificate");
  copy_casn(&certp->self, &EEcert.self);
  num_items(&signedDatap->certificates.self);
     // check CMS suffix
  char *c = strrchr(argv[2], (int)'.');
  if (!c || (strcmp(c, ".roa") && strcmp(c, ".man") && strcmp(c, ".mft") &&
    strcmp(c, ".mnf"))) 
    fatal(1, "CMSfile suffix");
       // fill in SignerInfo
  struct SignerInfo *signerInfop = (struct SignerInfo *)
    member_casn(&signedDatap->signerInfos.self, 0);
  if (!signerInfop) fatal(2, "SignerInfo");
  write_casn_num(&signerInfop->version.v3, 3);
      // add EE's SKI
  if (!(sextp = find_extension(&EEcert, id_subjectKeyIdentifier)))
    fatal(2, "EE certificate's subject key identifier");
  copy_casn(&signerInfop->sid.subjectKeyIdentifier, 
    &sextp->extnValue.subjectKeyIdentifier);
  write_objid(&signerInfop->digestAlgorithm.algorithm, id_sha256);
  write_casn(&signerInfop->digestAlgorithm.parameters.sha256, (uchar *)"", 0);
     // put in SignedAttrs
  clear_casn(&signerInfop->signedAttrs.self);
  struct Attribute *attrp = (struct Attribute *)inject_casn(
    &signerInfop->signedAttrs.self, 0);
       // content type
  write_objid(&attrp->attrType, id_contentTypeAttr);
  struct AttrTableDefined *attrTbDefp = (struct AttrTableDefined *)
    inject_casn(&attrp->attrValues.self, 0);
  copy_casn(&attrTbDefp->contentType, &signedDatap->encapContentInfo.
    eContentType);
         // digest alg
  attrp = (struct Attribute *)inject_casn( &signerInfop->signedAttrs.self, 1);
  write_objid(&attrp->attrType, id_messageDigestAttr);
      // hash
  attrTbDefp = (struct AttrTableDefined *) 
    inject_casn(&attrp->attrValues.self, 0);
  uchar hashbuf[40];
  uchar *tbh;
  int tbh_lth = readvsize_casn(&roa.content.signedData.encapContentInfo.
    eContent.self, &tbh); 
  tbh_lth = gen_hash(tbh, tbh_lth, hashbuf, CRYPT_ALGO_SHA2);
  free(tbh);
  write_casn(&attrTbDefp->messageDigest, hashbuf, tbh_lth);
  write_objid(&signerInfop->digestAlgorithm.algorithm, id_sha256);
  write_casn(&signerInfop->digestAlgorithm.parameters.sha256, (uchar *)"", 0);
      // signing time
  if (getenv("RPKI_NO_SIGNING_TIME") == NULL)
    {
    attrp = (struct Attribute *)inject_casn( &signerInfop->signedAttrs.self, 2);
    write_objid(&attrp->attrType, id_signingTimeAttr);
    time_t now = time(0);
    attrTbDefp = (struct AttrTableDefined *)
      inject_casn(&attrp->attrValues.self, 0);
    write_casn_time(&attrTbDefp->signingTime.utcTime, (ulong)now);
    }
       // sig alg
  write_objid(&signerInfop->signatureAlgorithm.algorithm, 
    id_sha_256WithRSAEncryption);
  write_casn(&signerInfop->signatureAlgorithm.parameters.
    sha256WithRSAEncryption, (uchar *)"", 0);
     // sign it!
  char *msg = signCMS(&roa, argv[3], 0);
  if (msg)
    fprintf(stderr, "%s\n", msg);
  else  // and write it
    if (argc < 5) put_casn_file(&roa.self, (char *)0, 1);
  else put_casn_file(&roa.self, argv[4], 0);
  return 0;
  }
