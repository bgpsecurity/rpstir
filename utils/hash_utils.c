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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int CryptInitState;

int gen_hash(unsigned char *inbufp, int bsize, unsigned char *outbufp, 
    CRYPT_ALGO_TYPE alg)
  { 
  CRYPT_CONTEXT hashContext;
  unsigned char hash[40];
  int ansr = -1;

  if (alg != CRYPT_ALGO_SHA && alg != CRYPT_ALGO_SHA2) return -1;
  memset(hash, 0, 40);
  if (!CryptInitState)
    {
    cryptInit();
    CryptInitState = 1;
    }

  cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2); 
  cryptEncrypt(hashContext, inbufp, bsize);
  cryptEncrypt(hashContext, inbufp, 0);
  cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ansr);
  cryptDestroyContext(hashContext);
  if (ansr > 0) memcpy(outbufp, hash, ansr);
  return ansr;
  }

