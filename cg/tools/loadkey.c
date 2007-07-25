#include <unistd.h>
#include <stdio.h>
#include "cryptlib.h"
#include <string.h>
#include <casn.h>
#include "privkey.h"

/* $Id$ */

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Verison 1.0
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
int fatal(char *msg)
  {
  if (msg && *msg) fprintf(stderr, "%s\n", msg);
  return 0;
  }

uchar *setmember(struct casn *mem, uchar *bufp, int *sizep)
  {
  if ((*sizep = read_casn(mem, bufp)) < 0) return (uchar *)0;
  if (*bufp == 0)
    {
    bufp++;
    (*sizep)--;
    }
  return bufp;
  }

int main(int argc, char **argv)
  {
  CRYPT_CONTEXT privKeyContext;
  CRYPT_KEYSET cryptKeyset;
  CRYPT_PKCINFO_RSA *rsakey;
  int ansr = 0;
  struct PrivateKey privkey;
  uchar *c, *buf;
  int bsize, nsize;

  if (argc < 4) fprintf(stderr, "Need argv[1] for label, [2] for .req file, [3] for outfile\n");
  else
    {
    cryptInit();
    ansr = cryptCreateContext(&privKeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA);
    PrivateKey(&privkey, 0);
    if (get_casn_file(&privkey.self, argv[2], 0) < 0) return fatal("Error getting key");
    bsize = size_casn(&privkey.n);
    buf = (uchar *)calloc(1, bsize);
    rsakey = malloc(sizeof(CRYPT_PKCINFO_RSA));
    cryptInitComponents(rsakey, CRYPT_KEYTYPE_PRIVATE);
    if (!(c = (uchar *)setmember(&privkey.n, buf, &nsize))) return fatal("Error getting n");
    cryptSetComponent(rsakey->n, c, nsize * 8);
    if (!(c = (uchar *)setmember(&privkey.e, buf, &nsize))) return fatal("Error getting e");
    cryptSetComponent(rsakey->e, c, nsize * 8);
    if (!(c = (uchar *)setmember(&privkey.d, buf, &nsize))) return fatal("Error getting d");
    cryptSetComponent(rsakey->d, c, nsize * 8);
    if (!(c = (uchar *)setmember(&privkey.p, buf, &nsize))) return fatal("Error getting p");
    cryptSetComponent(rsakey->p, c, nsize * 8);
    if (!(c = (uchar *)setmember(&privkey.q, buf, &nsize))) return fatal("Error getting q");
    cryptSetComponent(rsakey->q, c, nsize * 8);
    if (!(c = (uchar *)setmember(&privkey.u, buf, &nsize))) return fatal("Error getting u");
    cryptSetComponent(rsakey->u, c, nsize * 8);
    if (!(c = (uchar *)setmember(&privkey.e1, buf, &nsize))) return fatal("Error getting e1");
    cryptSetComponent(rsakey->e1, c, nsize * 8);
    if (!(c = (uchar *)setmember(&privkey.e2, buf, &nsize))) return fatal("Error getting e2");
    cryptSetComponent(rsakey->e2, c, nsize * 8);
    
    ansr = cryptSetAttributeString(privKeyContext, CRYPT_CTXINFO_LABEL, argv[1], 
      strlen(argv[1]));
    ansr = cryptSetAttributeString(privKeyContext, CRYPT_CTXINFO_KEY_COMPONENTS, rsakey, 
      sizeof(CRYPT_PKCINFO_RSA));
    ansr = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, argv[3], 
        CRYPT_KEYOPT_CREATE);
    ansr = cryptAddPrivateKey(cryptKeyset, privKeyContext, "password");
    ansr = cryptDestroyContext(privKeyContext);
    cryptEnd();
    }
  return 0;
  }

