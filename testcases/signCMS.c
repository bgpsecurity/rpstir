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

static struct casn *findSID(struct ROA *roap)
  {
  struct Certificate *certp = (struct Certificate *)member_casn(&roap->content.
    signedData.certificates.self, 0);
  struct Extensions *extsp = &certp->toBeSigned.extensions;
  struct Extension *extp;
  for (extp = (struct Extension *)member_casn(&extsp->self, 0);
    extp && diff_objid(&extp->extnID, id_subjectKeyIdentifier);
    extp = (struct Extension *)next_of(&extp->self));
  if (!extp) return (struct casn *)0;
  return &extp->extnValue.subjectKeyIdentifier;
  }

char * signCMS(struct ROA* roa, char *keyfilename, int bad)
  {
  CRYPT_CONTEXT hashContext;
  CRYPT_CONTEXT sigKeyContext;
  CRYPT_KEYSET cryptKeyset;
  uchar hash[40];
  uchar *signature = NULL;
  int ansr = 0, signatureLength;
  char *msg = (char *)0;
  uchar *tbsp;
  int tbs_lth = readvsize_casn(&roa->content.signedData.encapContentInfo.
    eContent.self, &tbsp);
  struct SignerInfo *sigInfop = (struct SignerInfo *)inject_casn(
      &(roa->content.signedData.signerInfos.self), 0);
  write_casn_num(&sigInfop->version.self, 3);
  struct casn *sidp = findSID(roa);
  if (!sidp) return "finding SID";
  copy_casn(&sigInfop->sid.subjectKeyIdentifier, findSID(roa));
  write_objid(&sigInfop->digestAlgorithm.algorithm, id_sha256);
  write_casn(&sigInfop->digestAlgorithm.parameters.sha256, (uchar *)"", 0);
  struct Attribute *attrp = (struct Attribute *)inject_casn(
    &sigInfop->signedAttrs.self, 0);
  write_objid(&attrp->attrType, id_contentTypeAttr);
  struct AttrTableDefined *attrtdp = (struct AttrTableDefined *)inject_casn(
    &attrp->attrValues.self, 0);
  write_objid(&attrtdp->contentType, id_routeOriginAttestation);
  attrp = (struct Attribute *)inject_casn( &sigInfop->signedAttrs.self, 1);
  write_objid(&attrp->attrType, id_messageDigestAttr);
   
  memset(hash, 0, 40);
  cryptInit();    // create the hash
  if ((ansr = cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2))
     != 0 || 
    (ansr = cryptCreateContext(&sigKeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA)) 
    != 0) msg = "creating context";
  else if ((ansr = cryptEncrypt(hashContext, tbsp, tbs_lth)) != 0 ||
  (ansr = cryptEncrypt(hashContext, tbsp, 0)) != 0) msg = "hashing";
        // get the hash
  else if ((ansr = cryptGetAttributeString(hashContext, 
    CRYPT_CTXINFO_HASHVALUE, hash, &signatureLength)) != 0 ||
    (ansr = cryptDeleteAttribute(hashContext, CRYPT_CTXINFO_HASHVALUE)) != 0)
    msg = "getting first hash";
  if (!msg)
    {
    attrtdp = (struct AttrTableDefined *)inject_casn(&attrp->attrValues.self, 
      0);
    write_casn(&attrtdp->messageDigest, hash, signatureLength);
    attrp = (struct Attribute *)inject_casn( &sigInfop->signedAttrs.self, 2);
    write_objid(&attrp->attrType, id_signingTimeAttr);
    attrtdp = (struct AttrTableDefined *)inject_casn(&attrp->attrValues.self, 
      0);
    write_casn_time(&attrtdp->signingTime.generalizedTime, 
      time((time_t*)0));
    tbs_lth = size_casn(&sigInfop->signedAttrs.self);
    free(tbsp);
    tbsp = (uchar *)calloc(1, tbs_lth);
    encode_casn(&sigInfop->signedAttrs.self, tbsp);
    *tbsp = ASN_SET;
    if ((ansr = cryptEncrypt(hashContext, tbsp, tbs_lth)) != 0 ||
        (ansr = cryptEncrypt(hashContext, tbsp, 0)) != 0)
      msg = "hashing";
          // get the hash
    if ((ansr = cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, 
      hash, &signatureLength)) != 0) msg = "getting second hash";
      
    else if ((ansr = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, 
      CRYPT_KEYSET_FILE, keyfilename, CRYPT_KEYOPT_READONLY)) != 0) 
      msg = "opening key set";
    else if ((ansr = cryptGetPrivateKey(cryptKeyset, &sigKeyContext, 
      CRYPT_KEYID_NAME, "label", "password")) != 0) msg = "getting key";
    else if ((ansr = cryptCreateSignature(NULL, 0, &signatureLength, 
      sigKeyContext, hashContext)) != 0) msg = "signing";
    else     // sign it
      {
      signature = (uchar *)calloc(1, signatureLength +20);
      if ((ansr = cryptCreateSignature(signature, 200, &signatureLength, 
        sigKeyContext, hashContext)) != 0) msg = "signing";
      else if ((ansr = cryptCheckSignature(signature, signatureLength, 
        sigKeyContext, hashContext)) != 0) msg = "verifying";
      }
    }

  cryptDestroyContext(hashContext);
  cryptDestroyContext(sigKeyContext);
  cryptEnd();
  if (ansr == 0)
    {
    struct SignerInfo sigInfo;
    SignerInfo(&sigInfo, (ushort)0); 
    decode_casn(&sigInfo.self, signature);
    if (bad)
      {
      uchar *sig;
      int siz = readvsize_casn(&sigInfo.signature, &sig);
      sig[0]++;
      write_casn(&sigInfo.signature, sig, siz);
      free(sig);
      }
    copy_casn(&sigInfop->signature, &sigInfo.signature);
    free(signature);
    write_objid(&sigInfop->signatureAlgorithm.algorithm, 
      id_rsadsi_rsaEncryption); 
    write_casn(&sigInfop->signatureAlgorithm.parameters.rsadsi_rsaEncryption, 
      (uchar *)"", 0);
    }
  return msg;
  }
