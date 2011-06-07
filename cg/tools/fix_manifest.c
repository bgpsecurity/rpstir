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
#include <sys/stat.h>
#include <certificate.h>
#include <roa.h>
#include <casn.h>

extern int gen_hash(uchar *inbufp, int bsize, uchar *outbufp, 
    CRYPT_ALGO_TYPE alg), 
    CryptInitState;

char *msgs [] = {
  "Finished OK\n",
  "Couldn't get %s\n",
  "Error hashing %s\n",   // 2
  "EEcert has no key identifier\n", 
  "Error signing in %s\n",
  }; 

static void fatal(int err, char *paramp)
  {
  fprintf(stderr, msgs[err], paramp);
  exit(0);
  }

struct keyring
  {
  char filename[80];
  char label[20];
  char password[20];
  };

static struct keyring keyring;
 
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
    cryptInit();
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
  if (argc < 4)
    {
    fprintf(stderr, "Usage: CMSfile EEkeyfile rehashFile(s)\n");
    return -1;
    }
  strcpy(keyring.label, "label");
  strcpy(keyring.password, "password");
  if (get_casn_file(&roa.self, argv[1], 0) < 0) 
    fatal(1, "CMS file");
  struct SignedData *signedDatap = &roa.content.signedData;
  char *c = strrchr(argv[1], (int)'.');
  if (!c || (strcmp(c, ".man") && strcmp(c, ".mft") && strcmp(c, ".mnf"))) 
    fatal(1, "CMSfile suffix");
  int i;
  char *fname;
  uchar hashbuf[40];
  uchar *tbh;
  int tbh_lth;
  struct Manifest *manp = &roa.content.signedData.encapContentInfo.eContent.
    manifest;
  for (fname = argv[i = 3]; fname; fname = argv[++i])
    {
    struct stat statbuf;
    struct FileAndHash *fahp;
    int j, fd;
    for (fahp = (struct FileAndHash *)member_casn(&manp->fileList.self, 0);
      fahp; fahp = (struct FileAndHash *)next_of(&fahp->self))
      {
      uchar *f;
      int fl = readvsize_casn(&fahp->file, &f);
      if (fl < 0) fatal(2, fname);
      if (fl == strlen(fname) && !strcmp((char *)f, fname)) break;
      } 
    if (!fahp || stat(fname, &statbuf) < 0 ||
      !(tbh = (uchar *)calloc(1, statbuf.st_size + 4)) ||
        (fd = open(fname, O_RDONLY)) < 0 ||
        (tbh_lth = read(fd, tbh, statbuf.st_size + 1)) < 0)
        fatal(1, fname);
    hashbuf[0] = 0;
    j = gen_hash(tbh, tbh_lth, &hashbuf[1], CRYPT_ALGO_SHA2);
    if (j < 0) fatal(2, fname); 
    free(tbh);
    write_casn(&fahp->hash, hashbuf, j + 1);
    }
       // fill in SignerInfo
  struct SignerInfo *signerInfop = (struct SignerInfo *)
    member_casn(&signedDatap->signerInfos.self, 0);
  if (!signerInfop) fatal(2, "SignerInfo");
  clear_casn(&signerInfop->signedAttrs.self);
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
  tbh_lth = readvsize_casn(&roa.content.signedData.encapContentInfo.
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
  char *msg = signCMS(&roa, argv[2], 0);
  if (msg)
    fprintf(stderr, "%s\n", msg);
  else
    put_casn_file(&roa.self, argv[1], 0);
  return 0;
  }
