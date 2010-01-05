/* $Id: signCMS.c 453 2008-07-25 15:30:40Z cgardiner $ */

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2008.  All Rights Reserved.
 *
 * Contributor(s):  Charles iW. Gardiner
 *
 * ***** END LICENSE BLOCK ***** */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <cryptlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <certificate.h>
#include <extensions.h>
#include <roa.h>
#include "roa_utils.h"

// find the SID for this ROA and return it
static struct casn *findSID(struct ROA *roap)
{
  struct Certificate *certp;
  struct Extensions *extsp;
  struct Extension *extp;

  // iterate through the roa's cert's extensions to find the SID
  certp = (struct Certificate *)member_casn(&roap->content. signedData.certificates.self, 0);
  extsp = &certp->toBeSigned.extensions;
  extp = (struct Extension *)member_casn(&extsp->self, 0); 

  // check each extension's oid against the SID oid
  while (extp != NULL) {
    if (diff_objid(&extp->extnID, id_subjectKeyIdentifier) == 0) {
      return(&extp->extnValue.subjectKeyIdentifier); /* found it */
    }
    extp = (struct Extension *)next_of(&extp->self); /* check next */
  }

  // not found
  return (struct casn *)0;
}

//
// sign a CMS (in this case a ROA)
// if bad == 1, intentionally generate a bad signature 
// return a printable message indicating the error (if any) or NULL if not
//
char * signCMS(struct ROA* roa, char *keyfilename, int bad)
{
  CRYPT_CONTEXT hashContext;
  CRYPT_CONTEXT sigKeyContext;
  CRYPT_KEYSET cryptKeyset;
  int signatureLength, tbs_lth;
  char *msg = (char *)0;
  uchar *tbsp, *signature, hash[40];
  struct casn *sidp;
  struct Attribute *attrp;
  struct AttrTableDefined *attrtdp;
  struct SignerInfo *sigInfop;

  // signer info
  // firat clear out any old stuff in signerInfos that may have been put
  // there by old code
  while(num_items(&roa->content.signedData.signerInfos.self) > 0)
    eject_casn(&roa->content.signedData.signerInfos.self, 0);
  sigInfop = (struct SignerInfo *)inject_casn(&(roa->content.signedData.signerInfos.self), 0);

  // write the signature version (3) to the signer info
  write_casn_num(&sigInfop->version.self, 3);

  // find the SID 
  if ((sidp = findSID(roa)) == NULL)
    return "finding SID";

  // copy the ROA's SID over to the signature's SID
  copy_casn(&sigInfop->sid.subjectKeyIdentifier, sidp);

  // use sha256 as the algorithm
  write_objid(&sigInfop->digestAlgorithm.algorithm, id_sha256);

  // no parameters to sha256
  write_casn(&sigInfop->digestAlgorithm.parameters.sha256, (uchar *)"", 0);

  // first attribute: content type
  attrp = (struct Attribute *)inject_casn(&sigInfop->signedAttrs.self, 0);
  write_objid(&attrp->attrType, id_contentTypeAttr);
  attrtdp = (struct AttrTableDefined *)inject_casn(&attrp->attrValues.self, 0);
  copy_casn(&attrtdp->contentType, &roa->content.signedData.encapContentInfo.
    eContentType);

  // second attribute: message digest
  attrp = (struct Attribute *)inject_casn( &sigInfop->signedAttrs.self, 1);
  write_objid(&attrp->attrType, id_messageDigestAttr);
   
  // create the hash for the content

  // first pull out the content
  if ((tbs_lth = readvsize_casn(&roa->content.signedData.encapContentInfo.eContent.self, &tbsp)) < 0)
    return "getting content";

  // set up the context, initialize crypt
  memset(hash, 0, 40);
  cryptInit();

  // the following calls function f, and if f doesn't return 0 sets
  // msg to m, then breaks out of the loop. Used immediately below.
#define CALL(f,m) if (f != 0) { msg = m; break; }

  // use a "do { ... } while (0)" loop to bracket this code, so we can
  // bail out on failure. (Note that this construct isn't really a
  // loop; it's a way to use break as a more clean version of goto.)
  do {
    // first sign the body of the message

    // create the context
    CALL(cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2), "creating context");

    // generate the hash
    CALL(cryptEncrypt(hashContext, tbsp, tbs_lth), "hashing");
    CALL(cryptEncrypt(hashContext, tbsp, 0), "hashing");

    // get the hash value. then we're done, so destroy it
    CALL(cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &signatureLength), "getting first hash");
    CALL(cryptDestroyContext(hashContext), "destroying intermediate context");

    // insert the hash as the first attribute
    attrtdp = (struct AttrTableDefined *)inject_casn(&attrp->attrValues.self, 0);
    write_casn(&attrtdp->messageDigest, hash, signatureLength);

    // create signing time attribute; mark the signing time as now
    attrp = (struct Attribute *)inject_casn( &sigInfop->signedAttrs.self, 2);
    write_objid(&attrp->attrType, id_signingTimeAttr);
    attrtdp = (struct AttrTableDefined *)inject_casn(&attrp->attrValues.self, 0);
    write_casn_time(&attrtdp->signingTime.utcTime, time((time_t*)0));

    // we are all done with the content
    free(tbsp);

    // now sign the attributes

    // get the size of signed attributes and allocate space for them
    if ((tbs_lth = size_casn(&sigInfop->signedAttrs.self)) < 0) 
      {
      msg = "sizing SignerInfo";
      break;
      }
    tbsp = (uchar *)calloc(1, tbs_lth);
    encode_casn(&sigInfop->signedAttrs.self, tbsp);
    *tbsp = ASN_SET;

    // create a new, fresh hash context for hashing the attrs, and hash them
    CALL(cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2), "creating hash context");
    CALL(cryptEncrypt(hashContext, tbsp, tbs_lth), "hashing attrs");
    CALL(cryptEncrypt(hashContext, tbsp, 0), "hashing attrs");

    // get the hash value
    CALL(cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &signatureLength), "getting attr hash");

    // get the key and sign it
    CALL(cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, keyfilename, CRYPT_KEYOPT_READONLY), "opening key set");
    CALL(cryptCreateContext(&sigKeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA), "creating RSA context");
    CALL(cryptGetPrivateKey(cryptKeyset, &sigKeyContext, CRYPT_KEYID_NAME, "label", "password"), "getting key");
    CALL(cryptCreateSignature(NULL, 0, &signatureLength, sigKeyContext, hashContext), "signing");

    // check the signature to make sure it's right
    signature = (uchar *)calloc(1, signatureLength +20);

    //  second parameter is signatureMaxLength, so we allow a little more
    CALL(cryptCreateSignature(signature, signatureLength+20, &signatureLength, sigKeyContext, hashContext), "signing");

    // verify that the signature is right
    CALL(cryptCheckSignature(signature, signatureLength, sigKeyContext, hashContext), "verifying");

    // end of protected block
  } while (0);

  // done with cryptlib, shut it down
  cryptDestroyContext(hashContext);
  cryptDestroyContext(sigKeyContext);
  cryptEnd();

  // did we have any trouble above? if so, bail
  if (msg != 0) {
    return msg;
  }

  // ok, write the signature back to the object
  struct SignerInfo sigInfo;
  SignerInfo(&sigInfo, (ushort)0); 
  decode_casn(&sigInfo.self, signature);

  // were we supposed to make a bad signature? if so, make it bad
  if (bad) {
	uchar *sig;
	int siz = readvsize_casn(&sigInfo.signature, &sig);
	sig[0]++;
	write_casn(&sigInfo.signature, sig, siz);
	free(sig);
      }

  // copy the signature into the object
  copy_casn(&sigInfop->signature, &sigInfo.signature);

  // all done with it now
  free(signature);

  // mark it as encrypted with rsa, no params
  write_objid(&sigInfop->signatureAlgorithm.algorithm, id_rsadsi_rsaEncryption); 
  write_casn(&sigInfop->signatureAlgorithm.parameters.rsadsi_rsaEncryption, (uchar *)"", 0);

  // no errors, we return NULL
  return NULL;
}
