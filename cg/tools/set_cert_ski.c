
/*
  $Id: set_cert_ski.c 453 2007-07-25 15:30:40Z gardiner $
*/


#include "roa_utils.h"
#include "manifest.h"
#include "cryptlib.h"
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

static int gen_hash(uchar *inbufp, int bsize, uchar *outbufp, int alg)
  { 
  CRYPT_CONTEXT hashContext;
  uchar hash[40];
  int ansr;

  memset(hash, 0, 40);
  if (cryptInit() != CRYPT_OK) return -1;
  if (alg == 2) cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2);
  else if (alg == 1) cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA);
  else return 0;
  cryptEncrypt(hashContext, inbufp, bsize);
  cryptEncrypt(hashContext, inbufp, 0);
  cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ansr);
  cryptDestroyContext(hashContext);
  cryptEnd();
  memcpy(outbufp, hash, ansr);
  return ansr;
  }

int main(int argc, char **argv)
  {
  struct Certificate cert;

  Certificate(&cert, (ushort)0);
  if (argc <= 1) 
    {
    fprintf(stderr, "Usage: input certificate file name, [output file name]\n");
    exit(0);
    }  
  if (get_casn_file(&cert.self, argv[1], 0) < 0)
    {
    fprintf(stderr, "error getting cert\n");
    return 0;
    }
  struct casn  *pubkp = &cert.toBeSigned.subjectPublicKeyInfo.subjectPublicKey;
  uchar *keyp;
  int klth = readvsize_casn(pubkp, &keyp);
  uchar khash[24];
  int ansr = gen_hash(&keyp[1], klth - 1, khash, 1);
  if (ansr < 0) 
    {
    fprintf(stderr, "Couldn't get CryptLib\n");
    return 0;
    }
  struct Extension *extp;
  for (extp = (struct Extension *)member_casn(&cert.toBeSigned.extensions.self, 0); extp; 
    extp = (struct Extension *)next_of(&extp->self))
    {
    if (!diff_objid(&extp->extnID, id_subjectKeyIdentifier)) break;
    }
  if (!extp) extp = (struct Extension *)member_casn(&cert.toBeSigned.extensions.self, 
    num_items(&cert.toBeSigned.extensions.self));
  write_objid(&extp->extnID, id_subjectKeyIdentifier);
  write_casn(&extp->extnValue.subjectKeyIdentifier, khash, ansr);
  char *c;
  if (put_casn_file(&cert.self, argv[2], 0) < 0) c = "error writing certificate\n";
  else c = "wrote certificate OK\n";
  fprintf(stderr, c);
  return 0;
  } 
