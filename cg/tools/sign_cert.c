#include <stdio.h>
#include <cryptlib.h>
#include <keyfile.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <certificate.h>
#include <roa.h>
#include <casn.h>

char *msgs[] = {
    "Finished %s OK\n",
    "Error in %s\n",
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
  if (argc < 3) 
    {
    fputs("Need 2 args: TBS filename, Key filename\n", stderr);
    return 0;
    }
  if (get_casn_file(&cert.self, argv[1], 0) < 0)
    {
    fprintf(stderr, "Couldn't open %s\n", argv[1]);
    return 0;
    }
  strcpy(keyring.label, "label");
  strcpy(keyring.password, "password");
  strcpy(keyring.filename, argv[2]);
  setSignature(&cert.toBeSigned.self, &cert.signature);
  put_casn_file(&cert.self, argv[1], 0);
  fatal(0, argv[1]);
  return 0;
  }
  
   
