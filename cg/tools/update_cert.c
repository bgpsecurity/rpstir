/* $Id: update_cert.c 453 2008-05-28 15:30:40Z cgardiner $ */

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
 * Contributor(s):  Charles W. Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "cryptlib.h"
#include "../asn/certificate.h"
#include <roa.h>
#include <keyfile.h>
#include <casn.h>
#include <asn.h>
#include <time.h>

char *msgs [] =
    {
    "Couldn't open %s\n",
    "Usage: startdelta, enddelta, certfile(s)\n",
    };

static char *units = "YMWDhms";

static int adjustTime(struct casn *timep, long basetime, char *deltap)
  {
  // if they passed in a NULL for deltap, just use basetime
  if (deltap != NULL) 
    {
    char *unitp = &deltap[strlen(deltap) - 1];
    if (*unitp == 'Z') 
      {
        // absolute time
      if (strlen(deltap) == 15) /* generalized time? */
            /* this fn doesn't handle generalizedtime, strip century */
            deltap += (15 - 13);
      else if (strlen(deltap) != 13) /* utc time? */
            return -1;      /* bad format */
      if (write_casn(timep, (uchar *)deltap, 13) < 0)
            return -1;      /* bad format */
      } 
    else if (strchr(units, *unitp) != 0) 
      {
        // relative time
      ulong val;
      sscanf(deltap, "%ld", &val);
      if (*unitp == 's') ;   // val is right
      else if (*unitp == 'm') val *= 60;
      else if (*unitp == 'h') val *= 3600;
      else if (*unitp == 'D') val *= (3600 * 24);
      else if (*unitp == 'W') val *= (3600 * 24 * 7);
      else if (*unitp == 'M') val *= (3600 * 24 * 30);
      else if (*unitp == 'Y') val *= (3600 * 24 * 365);
      basetime += val;
      write_casn_time(timep, (ulong)basetime);
      } 
    else return -1; // unknown delta unit, bad call
    }
  return 0;
  }

static int fatal(int err, char *param)
  {
  fprintf(stderr, msgs[err], param);
  exit(-1);
  }

static int setSignature(struct Certificate *certp, char *keyfile)
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

  if ((sign_lth = size_casn(&certp->toBeSigned.self)) < 0) fatal(5, "sizing");
  signstring = (uchar *)calloc(1, sign_lth);
  sign_lth = encode_casn(&certp->toBeSigned.self, signstring);
  memset(hash, 0, sizeof(hash));
  if (cryptInit() != CRYPT_OK) 
    {
    msg = "Couldn't get Cryptlib";
    ansr = -1;
    }
  else if ((ansr = cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2)) != 0 ||
      (ansr = cryptCreateContext(&sigKeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA)) != 0)
    msg = "creating context";
  else if ((ansr = cryptEncrypt(hashContext, signstring, sign_lth)) != 0 ||
      (ansr = cryptEncrypt(hashContext, signstring, 0)) != 0)
    msg = "hashing";
  else if ((ansr = cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash,
    &signatureLength)) != 0) msg = "getting attribute string";
  else if ((ansr = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, keyfile,
    CRYPT_KEYOPT_READONLY)) != 0) msg = "opening key set";
  else if ((ansr = cryptGetPrivateKey(cryptKeyset, &sigKeyContext, CRYPT_KEYID_NAME,
    "label", "password")) != 0) msg = "getting key";
  else if ((ansr = cryptCreateSignature(NULL, 0, &signatureLength, sigKeyContext,
    hashContext)) != 0) msg = "signing";
  else
    {
    signature = (uchar *)calloc(1, signatureLength +20);
    if ((ansr = cryptCreateSignature(signature, signatureLength+20,
      &signatureLength, sigKeyContext, hashContext)) != 0) msg = "signing";
    else if ((ansr = cryptCheckSignature(signature, signatureLength, sigKeyContext,
      hashContext)) != 0) msg = "verifying";
    }

  cryptDestroyContext(hashContext);
  cryptDestroyContext(sigKeyContext);
  cryptEnd();
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
      if ((ansr = write_casn_bits(&certp->signature, signstring, ansr, 0)) < 0)
        msg = "writing signature";
      else ansr = 0;
      }
    }
  if (signstring != NULL) free(signstring);
  if (signature != NULL ) free(signature);
  if (ansr) fatal(5, msg);
  return ansr;
  }

int main(int argc, char **argv)
  {
  struct Certificate cert;
  Certificate(&cert, (ushort)0);
  if (argc < 4) fatal(1, (char *)0);
  int i;
  for (i = 3; i < argc; i++)
    { 
    if (get_casn_file(&cert.self, argv[i], 0) < 0) fatal(0, argv[1]);
    struct CertificateToBeSigned *ctftbsp = &cert.toBeSigned;
  
    long now = time((time_t *)0);
    clear_casn(&ctftbsp->validity.notBefore.self);
    clear_casn(&ctftbsp->validity.notAfter.self);
    if (adjustTime(&ctftbsp->validity.notBefore.utcTime, now, argv[1]) < 0)
      fatal(9, argv[1]);
    if (adjustTime(&ctftbsp->validity.notAfter.utcTime, now, argv[2]) < 0)
      fatal(9, argv[2]);
    char *issuerkeyfile = (char *)calloc(1, strlen(argv[i]) + 8);
    strcpy(issuerkeyfile, argv[i]);
    char *a = strchr(issuerkeyfile, (int)'.');
    strcpy(&a[-1], ".p15");
    setSignature(&cert, issuerkeyfile);
    put_casn_file(&cert.self, argv[i], 0);
    fprintf(stderr, "Finished %s\n", argv[i]);
    }
  fprintf(stderr, "Finished all OK\n");
  return 0;
  }
