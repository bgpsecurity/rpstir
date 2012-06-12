/**
 * sign_cms - bare-bones CMS signing tool
 *
 * This is a bare-bones CMS signing tool.  It does NOT hash the
 * encapContentInfo to set the message digest in the signedAttrs
 * field.  It simply takes as input a user-provided private key and
 * the already-constructed signedAttrs.  It just hashes signedAttrs,
 * computes the RSA signature, and sets a signature value in the
 * SignerInfo.
 */

#include <stdio.h>
#include <cryptlib.h>
#include <stdlib.h>
#include "roa.h"
#include "logutils.h"


/* TODO: this function is duplicated from signCMS.c, due to
   dependencies on build-order (libroa cannot be linked in cg/tools).
   When we refactor, this function ought to be removed entirely.  */

static const char* signCMSBlob(struct CMSBlob *cms, const char *keyfilename)
{
  CRYPT_CONTEXT sigKeyContext;
  CRYPT_KEYSET cryptKeyset;
  CRYPT_CONTEXT hashContext;
  int tbs_lth;			/* to-be-signed length */
  unsigned char *tbsp = NULL;	/* to-be-signed pointer */
  unsigned char *hash[40];	/* stores sha256 message digest */
  int signatureLength;		/* RSA signature length */
  unsigned char *signature = NULL; /* RSA signature bytes */
  const char *errmsg = NULL;

  struct SignerInfo *signerInfop = (struct SignerInfo *)member_casn(
      &cms->content.signedData.signerInfos.self, 0);
  struct EncapsulatedContentInfo *encapContentInfop =
      &cms->content.signedData.encapContentInfo;

  if (vsize_casn(&signerInfop->signedAttrs.self) == 0) {
    if ((tbs_lth = vsize_casn(&encapContentInfop->eContent.self)) < 0) {
      errmsg = "sizing eContent";
      return errmsg;
    }
    tbsp = (unsigned char *)calloc(1, tbs_lth);
    if (!tbsp) {
      errmsg = "out of memory";
      return errmsg;
    }

    tbs_lth = read_casn(&encapContentInfop->eContent.self, tbsp);
  } else {
    // get the size of signed attributes and allocate space for them
    if ((tbs_lth = size_casn(&signerInfop->signedAttrs.self)) < 0) {
      errmsg = "sizing SignerInfo";
      return errmsg;
    }
    tbsp = (unsigned char *)calloc(1, tbs_lth);
    if (!tbsp) {
      errmsg = "out of memory";
      return errmsg;
    }

    // DER-encode signedAttrs
    tbs_lth = encode_casn(&signerInfop->signedAttrs.self, tbsp);
    *tbsp = ASN_SET; /* replace ASN.1 identifier octet with ASN_SET (0x31) */
  }

  // compute SHA-256 of signedAttrs
  if (cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2) < 0)
    errmsg = "creating hash context";
  else if (cryptEncrypt(hashContext, tbsp, tbs_lth) < 0 ||
	   cryptEncrypt(hashContext, tbsp, 0) < 0)
    errmsg = "hashing attrs";
  else if (cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE,
				   hash, &signatureLength) < 0)
    errmsg = "getting attr hash";

  // get the key and sign it
  else if(cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
			  keyfilename, CRYPT_KEYOPT_READONLY) < 0)
    errmsg =  "opening key set";
  else if(cryptCreateContext(&sigKeyContext, CRYPT_UNUSED,
			     CRYPT_ALGO_RSA) < 0)
    errmsg = "creating RSA context";
  else if(cryptGetPrivateKey(cryptKeyset, &sigKeyContext, CRYPT_KEYID_NAME,
			     "label", "password") < 0)
    errmsg = "getting key";
  else if(cryptCreateSignature(NULL, 0, &signatureLength, sigKeyContext,
			       hashContext) < 0)
    errmsg = "signing";

  // compute signature
  else if((signature = (unsigned char *)calloc(1, signatureLength +20)) == 0)
    errmsg = "out of memory";
  // second parameter is signatureMaxLength, so we allow a little more
  else if (cryptCreateSignature(signature, signatureLength+20, &signatureLength,
				sigKeyContext, hashContext) < 0)
    errmsg = "signing";
  // verify that the signature is right
  else if (cryptCheckSignature(signature, signatureLength, sigKeyContext,
			       hashContext) < 0)
    errmsg = "verifying";

  cryptDestroyContext(hashContext);
  cryptDestroyContext(sigKeyContext);

  if (!errmsg) {
    struct SignerInfo sigInfo;
    SignerInfo(&sigInfo, (ushort)0);
    decode_casn(&sigInfo.self, signature);
    // copy the signature into the object
    copy_casn(&signerInfop->signature, &sigInfo.signature);
    delete_casn(&sigInfo.self);
  }

  if (signature)
    free(signature);
  if (tbsp)
    free(tbsp);

  return errmsg;
}


int main(int argc, char **argv)
{
  const char *cmsfilename = NULL; /* to-be-signed CMS file */
  const char *keyfilename = NULL; /* p15 key file */
  const char *errmsg = NULL;
  struct CMSBlob cms;

  if (cryptInit() != CRYPT_OK) {
    log_msg(LOG_ERR, "could not initialize cryptlib");
    return -1;
  }

  /* parse arguments */
  if (argc != 3) {
    fprintf(stderr, "Usage: %s cmsfile keyfile\n", argv[0]);
    return -1;
  }
  cmsfilename = argv[1];
  keyfilename = argv[2];

  /* read CMS file */
  CMSBlob(&cms, (ushort)0);
  if (get_casn_file(&cms.self, (char *)cmsfilename, 0) < 0) {
    log_msg(LOG_ERR, "could not load %s", cmsfilename);
    return -1;
  }

  /* sign CMS */
  errmsg = signCMSBlob(&cms, keyfilename);
  if (errmsg) {
    log_msg(LOG_ERR, "error %s", errmsg);
    return -1;
  }

  /* write CMS file */
  if (put_casn_file(&cms.self, (char *)cmsfilename, 0) < 0) {
    log_msg(LOG_ERR, "could not write %s", cmsfilename);
    return -1;
  }

  delete_casn(&cms.self);

  return 0;
}
