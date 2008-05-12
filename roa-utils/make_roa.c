/*
  $Id: make_roa.c 453 2007-07-25 15:30:40Z gardiner $
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

char *msgs [] = 
    {
    "Created %s\n",
    "Can't open %s\n",      //1
    "Invalid prefix %s\n",
    "Missing %s\n",      // 3
    "%s covers AS number and v4 and v6 files\n",   
    "Error signng with %s\n",    // 5
    "Error writing %s\n",
    "Invalid parameter %s\n",     // 7
    };
    
static int fatal(int msg, char *paramp)
  {
  fprintf(stderr, msgs[msg], paramp);
  exit(msg);
  }

static int prefix2roa(struct ROAIPAddress *roaIPAddrp, char *prefixp, int family)
  {
  char *c;
  int pad = 0, siz;
  for (c = prefixp, siz = family; *c >= ' ' && *c != '/'; c++)
    {
    if (family == 1)
      {
      if (*c == '.') siz += 1;
      }
    else if (*c == ':') 
      {
      if (c[1] != ':') siz += 2;
      else if (pad) fatal(2, prefixp);
      else pad = 1;
      }
    }
  if (pad) pad = 16 - siz;
  uchar *buf = (uchar *)calloc(1, siz + pad + 2);
  uchar *b;
  int i;
  for (c = prefixp, b = &buf[1]; *c >= ' ' && *c != '/'; c++)
    {
    if (family == 1) 
      {
      sscanf(c, "%d", &i);
      *b++ = i;
      }
    else if (*c == ':') 
      {
      int j;
      for (j = 0; j < pad; *b++ = 0, j++);
      }
    else 
      {
      sscanf(c, "%x" , &i);
      *b++ = (uchar)(i >> 8);
      *b++ = (uchar)(i & 0xFF);
      }
    while(*c > ' ' && *c != '.' && *c != ':' && *c != '/') c++;
    if (*c == '/') break;
    }
  if (*c == '/') 
    {
    c++;
    sscanf(c, "%d", &i);
    while(*c >= '0' && *c <= '9') c++;
    siz += pad;
    } 
  int lim = (i + 7) / 8;
  if (siz < lim) fatal(2, prefixp);
  else if (siz > lim)
    {
    b--;
    if (*b) fatal(2, prefixp);
    siz--;
    }
  i = (8 * siz) - i;  // i = number of bits that don't count
  uchar x, y;
  for (x = 1, y = 0; x && y < i; x <<= 1, y++)
    {
    if (b[-1] & x) fatal(2, prefixp); 
    }
  buf[0] = i;
  write_casn(&roaIPAddrp->address, buf, siz + 1);
  if (*c == '^') 
    {
    sscanf(++c, "%d", &i);
    write_casn_num(&roaIPAddrp->maxLength, (long)i);
    }
  return siz;
  }

static void do_family(struct ROAIPAddrBlocks *roaBlockp, int famnum, int x, FILE *str)
  {
  struct ROAIPAddressFamily *roafamp = (struct ROAIPAddressFamily *)
    inject_casn(&roaBlockp->self, x);
  uchar family[2];
  char *c, nbuf[256];
  family[0] = 0;
  family[1] = famnum;
  write_casn(&roafamp->addressFamily, family, 2); 
  
  int numaddr;
  for (numaddr = 0; fgets(nbuf, sizeof(nbuf), str); numaddr++)
    {
    if (nbuf[0] > ' ') return;
    for (c = nbuf; *c == ' '; c++);
    struct ROAIPAddress *roaIPaddrp = (struct ROAIPAddress *)
      inject_casn(&roafamp->addresses.self, numaddr);
    prefix2roa(roaIPaddrp, c, famnum);
    }
  }    
  
static int signROA(struct ROA* roa, char *keyfilename)
  {
  CRYPT_CONTEXT hashContext;
  CRYPT_CONTEXT sigKeyContext;
  CRYPT_KEYSET cryptKeyset;
  uchar hash[40];
  uchar *signature = NULL;
  int ansr = 0, signatureLength;
  char *msg;
  uchar *tbsp;
  int tbs_lth = readvsize_casn(&roa->content.signedData.encapContentInfo.eContent.self, &tbsp);

  memset(hash, 0, 40);
  cryptInit();    // create the hash
  if ((ansr = cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2)) != 0 ||
      (ansr = cryptCreateContext(&sigKeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA)) != 0)
    msg = "creating context";
  else if ((ansr = cryptEncrypt(hashContext, tbsp, tbs_lth)) != 0 ||
      (ansr = cryptEncrypt(hashContext, tbsp, 0)) != 0)
    msg = "hashing";
        // get the hash
  else if ((ansr = cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, 
    &signatureLength)) != 0) msg = "getting attribute string";
  else if ((ansr = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, keyfilename, 
    CRYPT_KEYOPT_READONLY)) != 0) msg = "opening key set";
  else if ((ansr = cryptGetPrivateKey(cryptKeyset, &sigKeyContext, CRYPT_KEYID_NAME, "label", 
    "password")) != 0) msg = "getting key";
  else if ((ansr = cryptCreateSignature(NULL, 0, &signatureLength, sigKeyContext, hashContext)) != 0)
    msg = "signing";
  else     // sign it
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
    struct SignerInfo *sigInfop = (struct SignerInfo *)inject_casn(
        &(roa->content.signedData.signerInfos.self), 0);
    decode_casn(&sigInfop->self, signature);
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

int main (int argc, char ** argv)
  {
  struct ROA roa;

  if (argc < 2)
    {
    fprintf(stderr, "Need EITHER a parameter file name\n");
    fprintf(stderr, "OR -c certificateFile -k keyfile -o outputfile\n");
    fprintf(stderr, "    -r read_roa_outputfile or\n");
    return 0;
    }
  char *b, *c, *e, *buf = (char *)0;
  char *certfile, *keyfile, *outfile, *readroafile;
  certfile = keyfile = outfile = readroafile = (char *)0;
  if (argc == 2 && argv[1][0] != '-')  // parameter file
    {
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) fatal(1, argv[1]);
    int lth = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    buf = (char *)calloc(1, lth + 1);
    read(fd, buf, lth);
    for (e = buf; *e; e++) if (*e <= ' ') *e = 0;
    for (c = buf; c < e; c = b)
      {
      if (*c == '-')
        {
        c++;
        for (b = &c[1]; !*b && b < e; b++);
        if (!*b) fatal(7, c);
        if (*c == 'c') certfile = b;
        else if (*c == 'k') keyfile = b;
        else if (*c == 'o') outfile = b;
        else if (*c == 'r') readroafile = b;
        else fatal(7, &c[-1]);
        while (*b && b < e) b++;
        while (!*b && b < e) b++;
        }
      else fatal(7, c);
      }
    }
  else  // parameters as argvs
    {
    char **pp;
    for (pp = &argv[1]; *pp; pp++)
      {
      c = *pp;
      if (*c != '-') fatal(7,c);
      b = *(++pp);
      if (*c == 'c') certfile = b;
      else if (*c == 'k') keyfile = b;
      else if (*c == 'r') readroafile = b;
      else fatal(7, &c[-1]);
      }
    }
  if (!certfile)  fatal(3, "certificate file");
  if (!outfile)  fatal(3, "output file");
  if (!keyfile)  fatal(3, "key file");
  if (!readroafile) fatal(4, "readroafile");
  FILE *str = fopen(readroafile, "r");
  if (!str) fatal(1, readroafile);
  char nbuf[256];
  long asnum = -1;
  while(fgets(nbuf, 128, str))
    {
    if (!strncmp(nbuf, "AS#", 2))
      {
      for (c = &nbuf[3]; *c == ' '; c++);
      sscanf(c, "%ld", &asnum);
      break;
      }
    }
  fseek(str, 0, SEEK_SET);   
  ROA(&roa, (ushort )0);
  write_objid(&roa.contentType, id_signedData);
  struct SignedData *sgdp = &roa.content.signedData;
  write_casn_num((struct casn *)&sgdp->version, 3);
  struct AlgorithmIdentifier *algidp = (struct AlgorithmIdentifier *)
    inject_casn(&sgdp->digestAlgorithms.self, 0);
  write_objid(&algidp->algorithm, id_sha256);
  write_casn(&algidp->parameters.sha256, (uchar *)"", 0);
  write_objid(&sgdp->encapContentInfo.eContentType, id_routeOriginAttestation);
  struct RouteOriginAttestation *roap = &sgdp->encapContentInfo.eContent.roa;
  write_casn_num(&roap->asID, asnum);
  int x = 0;
  while ((c = fgets(nbuf, sizeof(nbuf), str)) && strncmp(nbuf, "IPv4", 4));
  if (c) do_family(&roap->ipAddrBlocks, 1, x++, str);
  fseek(str, 0, SEEK_SET);
  while ((c = fgets(nbuf, sizeof(nbuf), str)) && strncmp(nbuf, "IPv6", 4));
  if(c) do_family(&roap->ipAddrBlocks, 2, x, str);
  struct Certificate *certp = (struct Certificate *)
      inject_casn(&sgdp->certificates.self, 0);  
  if (get_casn_file(&certp->self, certfile, 0) < 0) fatal(2, certfile);
  if (signROA(&roa, keyfile) < 0) fatal(5, keyfile);
  if (put_casn_file(&roa.self, outfile, 0) < 0) fatal(6, outfile);
  if (buf) free(buf);
  fatal(0, outfile);
  return 0;
  }
