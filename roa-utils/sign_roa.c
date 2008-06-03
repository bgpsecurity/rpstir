/*
  $Id: manifest_validate.c 453 2007-07-25 15:30:40Z gardiner $
*/

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
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

#include "roa_utils.h"
#include "manifest.h"
#include "cryptlib.h"
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

/*
  This file has a program to sign manifests.
*/

char *msgs [] = 
    {
    "Finished OK\n",
    "Couldn't open %s\n",      //1
    "Error reading %s\n",
    "Error adding %s\n",      // 3
    "Error inserting %s\n",   
    "Error creating signature\n",    // 5
    "Error writing %s\n",
    };
    
static int gen_hash(uchar *inbufp, int bsize, uchar *outbufp)
  { 
  CRYPT_CONTEXT hashContext;
  uchar hash[40];
  int ansr;

  memset(hash, 0, 40);
  cryptInit();
  cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2);
  cryptEncrypt(hashContext, inbufp, bsize);
  cryptEncrypt(hashContext, inbufp, 0);
  cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ansr);
  cryptDestroyContext(hashContext);
  cryptEnd();
  memcpy(outbufp, hash, ansr);
  return ansr;
  }

static int fatal(int msg, char *paramp)
  {
  fprintf(stderr, msgs[msg], paramp);
  exit(msg);
  }

static int setSignature(struct ROA* roa, unsigned char* signstring, int lth, char *filename)
{
  CRYPT_CONTEXT hashContext;
  CRYPT_CONTEXT sigKeyContext;
  CRYPT_KEYSET cryptKeyset;
  uchar hash[40];
  uchar *signature = NULL;
  int ansr = 0, signatureLength;
  char *msg;

  memset(hash, 0, 40);
  cryptInit();
  if ((ansr = cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2)) != 0 ||
      (ansr = cryptCreateContext(&sigKeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA)) != 0)
    msg = "creating context";
  else if ((ansr = cryptEncrypt(hashContext, signstring, lth)) != 0 ||
      (ansr = cryptEncrypt(hashContext, signstring, 0)) != 0)
    msg = "hashing";
  else if ((ansr = cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, 
    &signatureLength)) != 0) msg = "getting attribute string";
  else if ((ansr = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, filename, 
    CRYPT_KEYOPT_READONLY)) != 0) msg = "opening key set";
  else if ((ansr = cryptGetPrivateKey(cryptKeyset, &sigKeyContext, CRYPT_KEYID_NAME, "label", 
    "password")) != 0) msg = "getting key";
  else if ((ansr = cryptCreateSignature(NULL, 0, &signatureLength, sigKeyContext, hashContext)) != 0)
    msg = "signing";
  else
    {
    signature = (uchar *)calloc(1, signatureLength +20);
    if ((ansr = cryptCreateSignature(signature, 200, &signatureLength, sigKeyContext,
      hashContext)) != 0) msg = "signing";
    else if ((ansr = cryptCheckSignature(signature, signatureLength, sigKeyContext, hashContext))
      != 0) msg = "verifying";
    }

  cryptDestroyContext(hashContext);
  cryptDestroyContext(sigKeyContext);
  cryptEnd();
  if (ansr == 0)
    { 
    decode_casn(&(roa->content.signedData.signerInfos.signerInfo.self), signature);
    ansr = 0;
    }
  else 
    {
      //  printf("Signature failed in %s with error %d\n", msg, ansr);
      // ansr = ERR_SCM_INVALSIG;
    }
  if ( signature != NULL ) free(signature);
  return ansr;
}


int main(int argc, char **argv)
  {
  struct ROA roa;

  if (argc < 4)
    {
    printf("Args needed: input file, key file, output file\n");
    return 0;
    } 
  ROA(&roa, 0);
  uchar *tbsp;
  if (get_casn_file(&roa.self, argv[1], 0) < 0) fatal(2, argv[1]);
  
  int tbs_lth = readvsize_casn(&roa.content.signedData.encapContentInfo.eContent.self, &tbsp);
  
  if (setSignature(&roa, tbsp, tbs_lth, argv[2]) < 0) fatal(5, (char *)0);
  if (put_casn_file(&roa.self, argv[3], 0) < 0) fatal(6, argv[3]);  
  return 0;
  } 
