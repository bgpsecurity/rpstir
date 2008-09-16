#include <unistd.h>
#include <stdio.h>
#include "cryptlib.h"
#include <string.h>

/* $Id: genkey.c 506 2008-06-03 21:20:05Z csmall $ */

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
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK ***** */
/*
int fatal(char *msg)
  {
  if (msg && *msg) fprintf(stderr, "%s\n", msg);
  exit(0);
  }
*/
int main(int argc, char **argv)
  {
  CRYPT_CONTEXT privKeyContext;
  CRYPT_KEYSET cryptKeyset;

  if (argc < 2) {
    fprintf(stderr, "Usage: Filename\n");
    return 1;
  }
  printf("Making %s\n", argv[1]);
  cryptInit();
  cryptCreateContext(&privKeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA);
  cryptSetAttributeString(privKeyContext, CRYPT_CTXINFO_LABEL, "label", 5);
  cryptSetAttribute(privKeyContext, CRYPT_CTXINFO_KEYSIZE, 1024/8);
  cryptGenerateKey(privKeyContext);
  cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, 
		  argv[1], CRYPT_KEYOPT_CREATE);
  cryptAddPrivateKey(cryptKeyset, privKeyContext, "password");
  cryptKeysetClose(cryptKeyset);
  cryptDestroyContext(privKeyContext);
  cryptEnd();

  return 0;
  }

