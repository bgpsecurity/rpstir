/*
  $Id: .dd_key_infoc c 506 2008-06-03 21:20:05Z gardiner $
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
#include <keyfile.h>
#include <casn.h>

char *msgs [] = {
  "Finished OK\n",
  "Couldn't open %s\n",
  "Couldn't find %s subject key identifier\n",    // 2
  "Usage: file names for certificate, subject key, [authority certificate]\n",
  "Subject and issuer differ in %s; need authority certificate\n", // 4
   }; 

static void fatal(int err, char *paramp)
  {
  fprintf(stderr, msgs[err], paramp);
  exit(0);
  }

static struct Extension *find_extension(struct Certificate *certp, char *idp,
  int creat)
  {
  struct Extension *extp;
  struct Extensions *extsp = &certp->toBeSigned.extensions;
  for (extp = (struct Extension *)member_casn(&extsp->self, 0);
    extp && diff_objid(&extp->extnID, idp);
    extp = (struct Extension *)next_of(&extp->self));
  if (!extp && creat)
    {
    int num = num_items(&extsp->self);
    extp = (struct Extension *)inject_casn(&extsp->self, num);
    if (extp) write_objid(&extp->extnID, idp);
    }  
  return extp;
  }

int CryptInitState;

static int gen_hash(uchar *inbufp, int bsize, uchar *outbufp, 
    CRYPT_ALGO_TYPE alg)
  { 
  CRYPT_CONTEXT hashContext;
  uchar hash[40];
  int ansr = -1;

  if (alg != CRYPT_ALGO_SHA && alg != CRYPT_ALGO_SHA2) return -1;
  memset(hash, 0, 40);
  if (!CryptInitState)
    {
    cryptInit();
    CryptInitState = 1;
    }

  cryptCreateContext(&hashContext, CRYPT_UNUSED, alg); 
  cryptEncrypt(hashContext, inbufp, bsize);
  cryptEncrypt(hashContext, inbufp, 0);
  cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ansr);
  cryptDestroyContext(hashContext);
  if (ansr > 0) memcpy(outbufp, hash, ansr);
  return ansr;
  }

int main(int argc, char **argv)
  {
  struct Certificate scert, acert;
  Certificate(&scert, (ushort)0);
  Certificate(&acert, (ushort)0);
  struct Keyfile keyfile;
  Keyfile(&keyfile, (ushort)0);
  if (argc < 3) fatal(3, (char *)0);
  if (get_casn_file(&scert.self, argv[1], 0) < 0) fatal(1, argv[1]); 
  if (get_casn_file(&keyfile.self, argv[2], 0) < 0) fatal(1, argv[2]);
  uchar *keyp;
  int ksiz = readvsize_casn(&keyfile.content.bbb.ggg.iii.nnn.ooo.ppp.key, 
    &keyp);
  uchar hashbuf[40];
  int hsize = gen_hash(&keyp[1], ksiz - 1, hashbuf, CRYPT_ALGO_SHA);
    
  struct Extension *aextp, *sextp;
  if (!(sextp = find_extension(&scert, id_subjectKeyIdentifier, 1)))
    fatal(2, "subject's");
  if (!(aextp = find_extension(&scert, id_authKeyId, 0))) fatal(2, "authority");
  write_casn(&sextp->extnValue.subjectKeyIdentifier, hashbuf, hsize);
  if (diff_casn(&scert.toBeSigned.subject.self, &scert.toBeSigned.issuer.self))
    {
    if (argc < 4) fatal(4, argv[1]);
    if (get_casn_file(&acert.self, argv[3], 0) < 0) fatal(1, argv[3]);
    if (!(sextp = find_extension(&acert, id_subjectKeyIdentifier, 0))) 
      fatal(2, "authority's");
    hsize = read_casn(&sextp->extnValue.subjectKeyIdentifier, hashbuf);
    }
  write_casn(&aextp->extnValue.authKeyId.keyIdentifier, hashbuf, hsize);
    
  write_casn(&scert.toBeSigned.subjectPublicKeyInfo.subjectPublicKey, keyp, 
    ksiz);
  put_casn_file(&scert.self, argv[1], 0);
  int siz = dump_size(&scert.self);
  char *buf = (char *)calloc(1, siz + 2);
  dump_casn(&scert.self, buf);
  char fname[80];
  strcpy(fname, argv[1]);
  strcat(fname, ".raw");
  int fd = creat(fname, 0777);
  write(fd, buf, siz);
  return 0;
  }
