/*
  $Id: make_TA.c c 506 2008-06-03 21:20:05Z gardiner $
*/

/* ***** BEGIN LICENSE BLOCK *****
 *
 * BBN Address and AS Number PKI Database/repository software
 * Version 3.0-beta
 *
 * US government users are permitted unrestricted rights as
 * defined in the FAR.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 2008-2010.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

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

#include "hashutils.h"

char *msgs [] = {
  "Finished OK\n",
  "Couldn't get %s\n",
  "Error inserting %s\n",   // 2
  "EEcert %s doesn't match ETA cert's\n", 
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

// return a printable message indicating the error (if any) or NULL if not
//
static char *signCMS(struct ROA* roa, char *keyfilename, int bad)
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
  // all done with it now
  if (signature) free(signature);
  return NULL;
  }

int main(int argc, char **argv)
  {
  struct ROA roa;
  ROA(&roa, (ushort)0);
  if (argc != 5)
    {
      fprintf(stderr, "Usage: %s ETAcert EEcert RTAcert EEkeyfile "
	      "> outfile.rta\n", argv[0]);
      return -1;
    }
  strcpy(keyring.label, "label");
  strcpy(keyring.password, "password");
  struct Certificate ETAcert, EEcert,RTAcert;
  Certificate(&ETAcert, (ushort)0);
  if (get_casn_file(&ETAcert.self, argv[1], 0) < 0) 
    fatal(1, "ETA certificate");
  Certificate(&EEcert, (ushort)0);
  if (get_casn_file(&EEcert.self, argv[2], 0) < 0) 
    fatal(1, "EE certificate");
  Certificate(&RTAcert, (ushort)0);
  if (get_casn_file(&RTAcert.self, argv[3], 0) < 0) 
    fatal(1, "RTA certificate");
  struct Extension *aextp, *sextp;
  if (!(aextp = find_extension(&ETAcert, id_subjectKeyIdentifier)) ||
    !(sextp = find_extension(&EEcert, id_authKeyId)) ||
    diff_casn(&aextp->extnValue.subjectKeyIdentifier,
      &sextp->extnValue.authKeyId.keyIdentifier)) fatal(3, "key identifier");
  if (diff_casn(&ETAcert.toBeSigned.subject.self,
    &EEcert.toBeSigned.issuer.self)) fatal(3, "name");
        // fill struct ROA up to SignerInfo
  write_objid(&roa.contentType, id_signedData);
  struct SignedData *signedDatap = &roa.content.signedData;
  write_casn_num(&signedDatap->version.v3, (long)3);
  struct CMSAlgorithmIdentifier *algp = (struct CMSAlgorithmIdentifier *)
    inject_casn(&signedDatap->digestAlgorithms.self, 0);
  write_objid(&algp->algorithm, id_sha256);
  write_casn(&algp->parameters.sha256, (uchar *)"", 0); 
  write_objid(&signedDatap->encapContentInfo.eContentType, 
    id_ct_RPKITrustAnchor);
  struct Certificate *rtacertp = 
    &signedDatap->encapContentInfo.eContent.trustAnchor;
  if (copy_casn(&rtacertp->self, &RTAcert.self) < 0) 
    fatal(2, "RTA certificate");
  struct Certificate *certp;
  if (!(certp = (struct Certificate *)inject_casn(
    &signedDatap->certificates.self, 0)) ||
    copy_casn(&certp->self, &EEcert.self) < 0) fatal(2, "EE certificate");
       // fill in SignerInfo
  struct SignerInfo *signerInfop = (struct SignerInfo *)
    inject_casn(&signedDatap->signerInfos.self, 0);
  if (!signerInfop) fatal(2, "SignerInfo");
  write_casn_num(&signerInfop->version.v3, 3);
  if (!(sextp = find_extension(&EEcert, id_subjectKeyIdentifier)))
    fatal(2, "EE certificate's subject key identifier");
  copy_casn(&signerInfop->sid.subjectKeyIdentifier, 
    &sextp->extnValue.subjectKeyIdentifier);
  write_objid(&signerInfop->digestAlgorithm.algorithm, id_sha256);
  write_casn(&signerInfop->digestAlgorithm.parameters.sha256, (uchar *)"", 0);
  struct Attribute *attrp = (struct Attribute *)inject_casn(
    &signerInfop->signedAttrs.self, 0);
  write_objid(&attrp->attrType, id_contentTypeAttr);
  struct AttrTableDefined *attrTbDefp = (struct AttrTableDefined *)
    inject_casn(&attrp->attrValues.self, 0);
  copy_casn(&attrTbDefp->contentType, &signedDatap->encapContentInfo.
    eContentType);
  attrp = (struct Attribute *)inject_casn( &signerInfop->signedAttrs.self, 1);
  write_objid(&attrp->attrType, id_messageDigestAttr);
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
  attrp = (struct Attribute *)inject_casn( &signerInfop->signedAttrs.self, 2);
  write_objid(&attrp->attrType, id_signingTimeAttr);
  time_t now = time(0);
  attrTbDefp = (struct AttrTableDefined *)
    inject_casn(&attrp->attrValues.self, 0);
  write_casn_time(&attrTbDefp->signingTime.utcTime, (ulong)now);
  write_objid(&signerInfop->signatureAlgorithm.algorithm, 
    id_rsadsi_rsaEncryption);
  write_casn(&signerInfop->signatureAlgorithm.parameters.rsadsi_rsaEncryption,
    (uchar *)"", 0);
  char *msg = signCMS(&roa, argv[4], 0);
  if (msg)
    fprintf(stderr, "%s\n", msg);
  else
    put_casn_file(&roa.self, (char *)0, 1);
  return 0;
  }
