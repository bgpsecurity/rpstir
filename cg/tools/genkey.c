#include <unistd.h>
#include <stdio.h>
#include "cryptlib.h"
#include <string.h>

/* $Id$ */

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
  int ansr = 0;

  if (argc < 3) fprintf(stderr, "Too few args\n");
  else
    {
    cryptInit();
    ansr = cryptCreateContext(&privKeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA);
    ansr = cryptSetAttributeString(privKeyContext, CRYPT_CTXINFO_LABEL, argv[2], strlen(argv[2]));
    ansr = cryptSetAttribute(privKeyContext, CRYPT_CTXINFO_KEYSIZE, 1024/8);
    ansr = cryptGenerateKey(privKeyContext);
    ansr = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, argv[1], CRYPT_KEYOPT_CREATE);
    ansr = cryptAddPrivateKey(cryptKeyset, privKeyContext, "");
    ansr = cryptDestroyContext(privKeyContext);
    cryptEnd();
    }
  return 0;
  }

