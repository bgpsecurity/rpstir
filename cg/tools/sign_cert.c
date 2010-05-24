/*
  $Id: sign_cert.c c 506 2008-06-03 21:20:05Z gardiner $
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
#include <certificate.h>
#include <crlv2.h>
#include <roa.h>
#include <casn.h>

char *msgs[] = {
    "Finished %s OK\n",
    "Error in %s\n",
    "Usage: TBS filename, Key filename\n",
    "Couldn't open %s\n",
    };

static void fatal(int err, char *paramp)
  {
  fprintf(stderr, msgs[err], paramp);
  exit(0);
  }

int CryptInitState = 0;

struct keyring
  {
  char filename[80];
  char label[10];
  char password[20];
  } keyring;

static int setSignature(struct casn *tbhash, struct casn *newsignature)
  {
  CRYPT_CONTEXT hashContext;
  CRYPT_CONTEXT sigKeyContext;
  CRYPT_KEYSET cryptKeyset;
  uchar hash[40];
  uchar *signature = NULL;
  int ansr = 0, signatureLength;
  char *msg;
  uchar *signstring = NULL;
  int sign_lth;

  if ((sign_lth = size_casn(tbhash)) < 0) fatal(1, "sizing");
  signstring = (uchar *)calloc(1, sign_lth);
  sign_lth = encode_casn(tbhash, signstring);
  memset(hash, 0, 40);
  if (!CryptInitState) 
    {
    cryptInit();
    CryptInitState = 1;
    }
  if ((ansr = cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2)) 
    != 0 ||
    (ansr = cryptCreateContext(&sigKeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA)) 
    != 0)
    msg = "creating context";
  else if ((ansr = cryptEncrypt(hashContext, signstring, sign_lth)) != 0 ||
      (ansr = cryptEncrypt(hashContext, signstring, 0)) != 0)
      msg = "hashing";
  else if ((ansr = cryptGetAttributeString(hashContext, 
      CRYPT_CTXINFO_HASHVALUE, hash,
      &signatureLength)) != 0) msg = "getting attribute string";
  else if ((ansr = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, 
      CRYPT_KEYSET_FILE, keyring.filename, CRYPT_KEYOPT_READONLY)) != 0) 
      msg = "opening key set";
  else if ((ansr = cryptGetPrivateKey(cryptKeyset, &sigKeyContext, 
      CRYPT_KEYID_NAME, keyring.label, keyring.password)) != 0) 
      msg = "getting key";
  else if ((ansr = cryptCreateSignature(NULL, 0, &signatureLength, 
      sigKeyContext, hashContext)) != 0) msg = "signing";
  else
    {
    signature = (uchar *)calloc(1, signatureLength +20);
    if ((ansr = cryptCreateSignature(signature, 200, &signatureLength, 
      sigKeyContext, hashContext)) != 0) msg = "signing";
    else if ((ansr = cryptCheckSignature(signature, signatureLength, 
      sigKeyContext, hashContext)) != 0) msg = "verifying";
    }
  cryptDestroyContext(hashContext);
  cryptDestroyContext(sigKeyContext);
  if (signstring) free(signstring);
  signstring = NULL;
  if (ansr == 0)
    {
    struct SignerInfo siginfo;
    SignerInfo(&siginfo, (ushort)0);
    if ((ansr = decode_casn(&siginfo.self, signature)) < 0)
      msg = "decoding signature";
    else if ((ansr = readvsize_casn(&siginfo.signature, &signstring)) < 0)
      msg = "reading signature";
    else
      {
      if ((ansr = write_casn_bits(newsignature, signstring, ansr, 0)) < 0)
        msg = "writing signature";
      else ansr = 0;
      }
    }
  if (signstring != NULL) free(signstring);
  if (signature != NULL ) free(signature);
  if (ansr) fatal(1, msg);
  return ansr;
  }

int main(int argc, char **argv)
  {
/*
 Args are: file TBS, keyfile
*/
  struct Certificate cert;
  Certificate(&cert, (ushort)0);
  struct CertificateRevocationList crl;
  CertificateRevocationList(&crl, (ushort)0);
  struct AlgorithmIdentifier *algp, *tbsalgp; 
  struct casn *casnp, *sigp, *selfp;
  if (argc < 3) fatal(2, (char *)0);
  char *sfx = strchr(argv[1], (int)'.'); 
  if (!strcmp(sfx, ".cer")) 
    {
    selfp = &cert.self;
    casnp = &cert.toBeSigned.self;
    tbsalgp = &cert.toBeSigned.signature;
    sigp = &cert.signature;
    algp = &cert.algorithm;
    }
  else if (!strcmp(sfx, ".crl"))
    {
    selfp = &crl.self;
    casnp = &crl.toBeSigned.self;
    tbsalgp = &crl.toBeSigned.signature;
    sigp = &crl.signature;
    algp = &crl.algorithm;
    }
  if (get_casn_file(selfp, argv[1], 0) < 0) fatal(3, argv[1]);
  write_objid(&tbsalgp->algorithm, id_sha_256WithRSAEncryption);
  write_casn(&tbsalgp->parameters.rsadsi_SHA256_WithRSAEncryption, 
    (uchar *)"", 0);
  strcpy(keyring.label, "label");
  strcpy(keyring.password, "password");
  strcpy(keyring.filename, argv[2]);
  setSignature(casnp, sigp);
  write_objid(&algp->algorithm, id_sha_256WithRSAEncryption);
  write_casn(&algp->parameters.rsadsi_SHA256_WithRSAEncryption, 
    (uchar *)"", 0);
  put_casn_file(selfp, argv[1], 0);
  fatal(0, argv[1]);
  return 0;
  }
