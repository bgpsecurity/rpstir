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
  "Error inserting %s\n",   // 2
  "Couldn't find %s key identifier\n", 
  "Error signing in %s\n",     // 4
  "Need authority's certificate\n",
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
 
static struct Extension *find_extension(struct Certificate *certp, char *idp)
  {
  struct Extension *extp;
  for (extp = (struct Extension *)member_casn(
    &certp->toBeSigned.extensions.self, 0);
    extp && diff_objid(&extp->extnID, idp);
    extp = (struct Extension *)next_of(&extp->self));
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
  if (argc < 3)
    {
    fputs("Need file names for certificate, subject key and optional authority key\n", stderr);
    return -1;
    }
  if (get_casn_file(&scert.self, argv[1], 0) < 0) fatal(1, argv[1]); 
  if (get_casn_file(&keyfile.self, argv[2], 0) < 0) fatal(1, argv[2]);
  uchar *keyp;
  int ksiz = readvsize_casn(&keyfile.content.bbb.ggg.iii.nnn.ooo.ppp.key, &keyp);
  uchar hashbuf[40];
  int hsize = gen_hash(&keyp[1], ksiz - 1, hashbuf, CRYPT_ALGO_SHA);
    
  struct Extension *aextp, *sextp;
  if (!(sextp = find_extension(&scert, id_subjectKeyIdentifier)))
    fatal(3, "subject");
  if (!(aextp = find_extension(&scert, id_authKeyId))) fatal(3, "authority");
  write_casn(&sextp->extnValue.subjectKeyIdentifier, hashbuf, hsize);
  if (diff_casn(&scert.toBeSigned.subject.self, &scert.toBeSigned.issuer.self))
    {
    if (argc < 4) fatal(5, "");
    if (get_casn_file(&acert.self, argv[3], 0) < 0) fatal(1, argv[3]);
    if (!(sextp = find_extension(&acert, id_subjectKeyIdentifier))) fatal(3, "authority's subject");
    hsize = read_casn(&sextp->extnValue.subjectKeyIdentifier, hashbuf);
    }
  write_casn(&aextp->extnValue.authKeyId.keyIdentifier, hashbuf, hsize);
    
  write_casn(&scert.toBeSigned.subjectPublicKeyInfo.subjectPublicKey, keyp, ksiz);
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
