/* $Id: make_cert.c 453 2008-05-28 15:30:40Z cgardiner $ */

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
    "Finished %s OK\n",
    "Couldn't open %s\n",
    "Can't translate %s.  Try again\n",      // 2
    "Usage: subjectname startdelta enddelta\n [b(ad signature) | e(xplicit IP) | n(either)]\n",
    "Issuer cert has no %s extension\n",              // 4
    "Signing failed in %s\n",
    "Error opening %s\n",                // 6
    "Error reading IP Address Family\n",
    "Error padding prefix %s. Try again\n",       // 8
    "Invalid time delta type: %s\n",
    "Invalid cert name %s\n",             // 10
    "Error creating %s extension\n",
    "Error in CA %s extension\n",      // 12
    "Invalid parameter %s\n",
    };

static int warn(int err, char *param)
  {
  fprintf(stderr, msgs[err], param);
  return -1;
  }

static void fatal(int err, char *param)
  {
  warn(err, param);
  exit(err);
  }

extern int adjustTime(struct casn *timep, long now, char *deltap);

static int fillPublicKey(struct casn *spkp, char *keyfile)
  {
  struct Keyfile kfile;
  Keyfile(&kfile, (ushort)0);
  if (get_casn_file(&kfile.self, keyfile, 0) < 0)
    fatal(1, keyfile);
  copy_casn(spkp, &kfile.content.bbb.ggg.iii.nnn.ooo.ppp.key);
  return 0;
  }

static void check_access_methods(struct Extension *iextp)
  {
  int rep = 0, man = 0;
  char *e = "SubjectInfoAccess";
  struct AccessDescription *accDesp;
  if (num_items (&iextp->extnValue.subjectInfoAccess.self) != 2) fatal(12, e);
   // are the two necessary access methods there?
  for (accDesp = (struct AccessDescription *)member_casn(
    &iextp->extnValue.subjectInfoAccess.self, 0); accDesp;
    accDesp = (struct AccessDescription *)next_of(&accDesp->self))
    {
    if (!diff_objid(&accDesp->accessMethod, id_ad_caRepository)) rep++;
    else if (!diff_objid(&accDesp->accessMethod, id_ad_rpkiManifest)) man++;
    else man = 10; // to force error if neither
    }
  if (rep != 1 && man != 1) fatal(12, e);
  }

static struct Extension *findExtension(struct Extensions *extsp, char *oid)
  {
  struct Extension *extp;
  if (!num_items(&extsp->self)) return (struct Extension *)0;
  for (extp = (struct Extension *)member_casn(&extsp->self, 0);
    extp && diff_objid(&extp->extnID, oid);
    extp = (struct Extension *)next_of(&extp->self));
  return extp;
  }

static int gen_hash(uchar *inbufp, int bsize, uchar *outbufp, int alg)
  {
  CRYPT_CONTEXT hashContext;
  uchar hash[40];
  int ansr;

  memset(hash, 0, 40);
  cryptInit();
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

static void inheritIPAddresses(struct Extension *extp, struct Extension *iextp)
  {
  struct IPAddressFamilyA *ipfamp;
  int num;
  copy_casn(&extp->self, &iextp->self);
  num = num_items(&extp->extnValue.ipAddressBlock.self);
  for (num--; num >= 0; num--)
    {    // first clear out the real addresses
    ipfamp = (struct IPAddressFamilyA *)member_casn(
      &extp->extnValue.ipAddressBlock.self, num);
    while(num_items(&ipfamp->ipAddressChoice.addressesOrRanges.self) > 0)
      eject_casn(&ipfamp->ipAddressChoice.addressesOrRanges.self, 0);
      // then set inherit
    write_casn(&ipfamp->ipAddressChoice.inherit, (uchar *)"", 0);
    }
  }

static int ip2Prefix(char **prefixpp, struct IPAddressA *ipp, int family)
  {
  int lth = vsize_casn(ipp);
  if (lth <= 0) return -1;
  int bsize = (lth * 5) + 30; // on the safe side
  char *buf = (char *)calloc(1, bsize);
  uchar *abuf;
  int asize = readvsize_casn(ipp, &abuf);
  uchar *e, *u;
  char *c;
  int i;
  for (u = &abuf[1], e = &abuf[asize], c = buf; u < e; u++)
    {
    if (family == 1) c += sprintf(c, "%d.", (int)*u);
    else
      {
      i = (*u++ << 8);
      if (u < e) i += *u;
      c += sprintf(c, "%04x:", i);
      }
    }
  c--; //cut of final '.' or ':'
  i = (asize - 1) * 8; // total bits
  i -= abuf[0];       // used bits
  c += sprintf(c, "/%d", i);
  while(*c) c++;
  *c++ = '\n';
  *c = 0;
  free(abuf);
  *prefixpp = buf;
  return (c - buf);
  }

static int ipOrRange2prefix(char **prefixpp, struct IPAddressOrRangeA *ipp, int family)
  {
  if (size_casn(&ipp->addressPrefix) > 0)
    return ip2Prefix(prefixpp, &ipp->addressPrefix, family);
  char *a;
  int ansr = ip2Prefix(&a, &ipp->addressRange.min, family);
  char *b;
  int ansr2 = ip2Prefix(&b, &ipp->addressRange.max, family);
  a = (char *)realloc(a, ansr + ansr2);
  strcpy(&a[ansr2], b);
  free(b);
  return ansr + ansr2;
  }

static struct Extension *makeExtension(struct Extensions *extsp, char *idp)
  {
  struct Extension *extp;
  if (!(extp = findExtension(extsp, idp)))
    {
    extp = (struct Extension *)inject_casn(&extsp->self,
      num_items(&extsp->self));
    }
  else clear_casn(&extp->self);
  write_objid(&extp->extnID, idp);
  return extp;
  }

static int prefix2ip(struct IPAddressA *iPAddrp, char *prefixp, int family)
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
      else if (pad) return warn(2, prefixp);
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
  if (siz < lim) return warn(8, prefixp);
  else if (siz > lim)
    {
    b--;
    if (*b) return warn(2, prefixp);
    siz--;
    }
  i = (8 * siz) - i;  // i = number of bits that don't count
  uchar x, y;
  for (x = 1, y = 0; x && y < i; x <<= 1, y++)
    {
    if (b[-1] & x) return warn(2, prefixp);
    }
  buf[0] = i;
  write_casn(iPAddrp, buf, siz + 1);
  return siz;
  }

static void read_ASNums(char **app, struct ASNum *asNump)
  {
  int num = 0;
  struct ASNumberOrRangeA *asNumOrRangep;
  char *a = (char *)calloc(1, 256);
  char *b = a;
  for (asNumOrRangep  = (struct ASNumberOrRangeA *)member_casn(
    &asNump->asnum.asNumbersOrRanges.self, num++); asNumOrRangep;
    asNumOrRangep = (struct ASNumberOrRangeA *)next_of(&asNumOrRangep->self))
    {
    long val;
    if (size_casn(&asNumOrRangep->num) > 0)
      {
      read_casn_num(&asNumOrRangep->num, &val);
      sprintf(b, "%ld\n", val);
      }
    else
      {
      read_casn_num(&asNumOrRangep->range.min, &val);
      sprintf(b, "%ld-", val);
      while (*b) b++;
      read_casn_num(&asNumOrRangep->range.max, &val);
      sprintf(b, "%ld\n", val);
      }
    while(*b) b++ ;
    }
  *app = a;
  }

static int read_family(char **fampp, struct IPAddressFamilyA *famp)
  {
  uchar ub[8];
  read_casn(&famp->addressFamily, ub);
  int bsize = 100;
  char *a, *c, *buf = (char *)calloc(1, bsize);
  strcpy(buf, "IPv4\n");
  if (ub[1] == 2) buf[3] = '6';
  c = &buf[5];
  int i, num = num_items(&famp->ipAddressChoice.addressesOrRanges.self);
  for (i = 0; i < num; i++)
    {
    struct IPAddressOrRangeA *ipp = (struct IPAddressOrRangeA *)
      member_casn(&famp->ipAddressChoice.addressesOrRanges.self, i);
    if (!ipp) fatal(1, buf);
    int lth = ipOrRange2prefix(&a, ipp, (int) ub[1]);
    if (lth <= 0) fprintf(stderr, "Error in address[%d] in IPv%c\n", i, buf[3]);
    else
      {
      if (&c[lth + 8] >= &buf[bsize])
        {
        int clth = (c - buf);
        buf = (char *)realloc(buf, bsize += lth);
        c = &buf[clth];
        }
      strcpy(c, a);
      c += lth;
      free(a);
      }
    }
  *fampp = buf;
  return strlen(buf);
  }

static void set_name(struct RDNSequence *rdnsp, char *namep)
  {
  clear_casn(&rdnsp->self);
  struct RelativeDistinguishedName *rdnp = (struct RelativeDistinguishedName *)
    inject_casn(&rdnsp->self, 0);
  struct AttributeValueAssertion *avap = (struct AttributeValueAssertion *)inject_casn(
    &rdnp->self, 0);
  write_objid(&avap->objid, id_commonName);
  write_casn(&avap->value.commonName.printableString, (uchar *)namep, strlen(namep));
  }

static int setSignature(struct Certificate *certp, char *keyfile, int bad)
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
  memset(hash, 0, 40);
  cryptInit();
  if ((ansr = cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2)) != 0 ||
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
    if ((ansr = cryptCreateSignature(signature, 200, &signatureLength, sigKeyContext,
      hashContext)) != 0) msg = "signing";
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
      if (bad) signstring[0]++;
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

static void write_ASNums(struct ASNum *asnump)
  {
  char *a, nbuf[100];
  int ansr, num;
  for (ansr = num = 0; fgets(nbuf, 100, stdin) && nbuf[0] > ' '; )
    {
    struct ASNumberOrRangeA  *asNumorRangep;
    if (ansr >= 0) asNumorRangep = (struct ASNumberOrRangeA *)
      inject_casn(&asnump->asnum.asNumbersOrRanges.self, num++);
    ansr = 0;
    for (a = nbuf; *a > ' '; a++);
    *a = 0;
    for (a = nbuf; *a && (*a == '-' || (*a >= '0' && *a <= '9')); a++);
    if (*a)
      {
      fprintf(stderr, "Invalid number(s).  Try again\n");
      ansr = -1;
      continue;
      }
    for (a = nbuf; *a && *a != '-'; a++);
    int val;
    if (!*a)
      {
      if (sscanf(nbuf, "%d", &val) != 1 ||
        write_casn_num(&asNumorRangep->num, val) <= 0) ansr = -1;
      }
    else
      {
      if (sscanf(nbuf, "%d", &val) != 1 ||
        write_casn_num(&asNumorRangep->range.min, val) <= 0 ||
        sscanf(++a, "%d", &val) != 1 ||
        write_casn_num(&asNumorRangep->range.max, val) <= 0) ansr = -1;
      }
    }
  }

static int write_family(struct IPAddressFamilyA *famp, int filein)
  {
  uchar family[2];
  char nbuf[256];
  read_casn(&famp->addressFamily, family);
  write_casn(&famp->addressFamily, family, 2);
  char *a;
  int f = (family[1]== 1)? 4: 6;
  if (!filein) fprintf(stdout, "What prefixes for family IPv%d?\n", f);
  int ansr = 0;
  int num;
  for (num = 0; fgets(nbuf, 100, stdin) && nbuf[0] > ' '; )
    {
    struct IPAddressOrRangeA *ipAorRp;
    if (ansr >= 0) ipAorRp = (struct IPAddressOrRangeA *)inject_casn(
        &famp->ipAddressChoice.addressesOrRanges.self, num++);
    for (a = nbuf; *a > ' '; a++);
    *a = 0;
    for (a = nbuf; *a && *a != '-'; a++);
    if (!*a) ansr = prefix2ip(&ipAorRp->addressPrefix, nbuf, (int)family[1]);
    else
      {
      if ((ansr = (prefix2ip(&ipAorRp->addressRange.min, nbuf, (int)family[1]))) >= 0)
          ansr = prefix2ip(&ipAorRp->addressRange.max, a, (int)family[1]);
      }

    }
  return num;
  }

static int writeHashedPublicKey(struct casn *valuep, struct casn *keyp, char x)
  {
  uchar *bitval;
  int siz = readvsize_casn(keyp, &bitval);
  uchar hashbuf[24];
  siz = gen_hash(&bitval[1], siz - 1, hashbuf, 1);
  free(bitval);
  if (x) hashbuf[0]++;
  write_casn(valuep, hashbuf, siz);
  return siz;
  }
/*
static void view_extensions(struct Extensions *extsp)
  {
  struct Extension *extp;
  for (extp = (struct Extension *)member_casn(&extsp->self, 0); extp;
    extp = (struct Extension *)next_of(&extp->self))
    {
    char id[20];
    read_objid(&extp->extnID, id);
    printf("%s\n", id);
    }
  }
*/
int main(int argc, char **argv)
  {
  if (argc < 4 || argc > 5) fatal(3, "");
  int bad = 0, ee = 0, root = (strlen(argv[1]) == 1), explicitIPAS = 0;
  struct stat tstat;
  fstat(0, &tstat);
  int filein = (tstat.st_mode & S_IFREG);
  struct Certificate cert;
  struct Certificate issuer;
  Certificate(&cert, (ushort)0);
  struct CertificateToBeSigned *ctftbsp = &cert.toBeSigned;
  Certificate(&issuer, (ushort)0);
  char *c, *subjkeyfile, *subjfile, *issuerfile = (char *)0,
    *issuerkeyfile = (char *)0, skistat = (char)0;
  if (argc > 4) 
    {
    if (argv[4][0] == 'b') bad = 1;
    else if (argv[4][0] == 'e') explicitIPAS = 1; // copy addresses
    else if (argv[4][0] == 'n') explicitIPAS = -1; // no IP or AS extensions
    else if (argv[4][0] == 'x') skistat = 'x';
    else fatal(13, argv[4]);
    }
  for (c = &argv[1][1]; *c && *c >= '0' && *c <= '9'; c++);
  if (*c && *c != 'M' && *c != 'R') fatal(10, argv[1]);
  if (*c) ee = 1;
  subjfile = (char *)calloc(1, strlen(argv[1]) + 8);
  subjkeyfile = (char *)calloc(1, strlen(argv[1]) + 8);
         // get keyfile for subject public key
  strcat(strcpy(subjkeyfile, argv[1]), ".p15");
  strcat(strcpy(subjfile, argv[1]), ".cer");
  int snum = 1;
  if (root)
    {
    if (get_casn_file(&cert.self, subjfile, 0) < 0) fatal(1, subjfile);
    write_casn_num(&ctftbsp->serialNumber, (long)1);
    }
  else
    {
    // start filling subject cert
    write_casn_num(&ctftbsp->version.self, 2);
    char *a = argv[1];        // get the issuer file
    for (a++; *a >= '0' && *a <= '9'; a++);
    if (!*a) a--;   // if not EE, cut off lest digit for issuer
    issuerfile = (char *)calloc(1, strlen(argv[1]) + 8);
    strcat(strncpy(issuerfile, argv[1], a - argv[1]), ".cer");
    issuerkeyfile = (char *)calloc(1, strlen(argv[1]) + 8);
    strcat(strncpy(issuerkeyfile, argv[1], a - argv[1]), ".p15");
    if (get_casn_file(&issuer.self, issuerfile, 0) < 0)
      fatal(1, issuerfile);
    for (c = issuerfile; *c && *c != '.'; c++);
    strcpy(c, ".p15");
    sscanf(subjfile, "C%d", &snum);
    snum++;
    if (*a == 'M') snum += 0x100;
    if (*a == 'R') snum += 0x200;
    write_casn_num(&ctftbsp->serialNumber, (long)snum);
    copy_casn(&cert.algorithm.self, &issuer.toBeSigned.signature.self);
    copy_casn(&ctftbsp->signature.self, &issuer.toBeSigned.signature.self);
    copy_casn(&ctftbsp->issuer.self, &issuer.toBeSigned.subject.self);
    }
  set_name(&ctftbsp->subject.rDNSequence, argv[1]);

  long now = time((time_t *)0);
  clear_casn(&ctftbsp->validity.notBefore.self);
  clear_casn(&ctftbsp->validity.notAfter.self);
  if (adjustTime(&ctftbsp->validity.notBefore.utcTime, now, argv[2]) < 0)
    fatal(9, argv[2]);
  if (adjustTime(&ctftbsp->validity.notAfter.utcTime, now, argv[3]) < 0)
    fatal(9, argv[3]);

  struct SubjectPublicKeyInfo *spkinfop = &ctftbsp->subjectPublicKeyInfo;
  write_objid(&spkinfop->algorithm.algorithm, id_rsadsi_rsaEncryption);
  write_casn(&spkinfop->algorithm.parameters.rsadsi_rsaEncryption, (uchar *)"",  0);
  struct casn *spkp = &spkinfop->subjectPublicKey;
  fillPublicKey(spkp, subjkeyfile);

  struct Extensions *extsp = &ctftbsp->extensions, *iextsp;
  if (issuerkeyfile) iextsp = &issuer.toBeSigned.extensions;
  else iextsp = NULL;
  struct Extension *extp, *iextp;
       // make subjectKeyIdentifier first
  extp = makeExtension(extsp, id_subjectKeyIdentifier);
  writeHashedPublicKey(&extp->extnValue.subjectKeyIdentifier, spkp, skistat);
  if (issuerkeyfile)
    {
    // key usage
    extp = makeExtension(extsp, id_keyUsage);
    if (!(iextp = findExtension(iextsp, id_keyUsage)))
      fatal(4, "key usage");
    copy_casn(&extp->self, &iextp->self);
    if (ee)
      {
      write_casn(&extp->extnValue.keyUsage.self, (uchar *)"", 0);
      write_casn_bit(&extp->extnValue.keyUsage.digitalSignature, 1);
      }
    // basic constraints
    if (!ee)
      {
      extp = makeExtension(extsp, id_basicConstraints);
      if (!(iextp = findExtension(iextsp, id_basicConstraints)))
        fatal(4, "basic constraints");
      copy_casn(&extp->self, &iextp->self);
      }
      // CRL dist points
    extp = makeExtension(extsp, id_cRLDistributionPoints);
    if (!(iextp = findExtension(iextsp, id_cRLDistributionPoints)))
      fatal(4, "CRL Dist points");
    copy_casn(&extp->self, &iextp->self);
      // Cert policies
    extp = makeExtension(extsp, id_certificatePolicies);
    if (!(iextp = findExtension(iextsp, id_certificatePolicies)))
      fatal(4, "cert policies");
    copy_casn(&extp->self, &iextp->self);
      // authInfoAccess
    extp = makeExtension(extsp, id_pkix_authorityInfoAccess);
    if (strlen(argv[1]) == 2 || (strlen(argv[1]) == 3 && argv[1][1] > '9'))
      {  // first generation.  Have to build it
      struct AuthorityInfoAccessSyntax *aiasp = &extp->extnValue.authorityInfoAccess;
      struct AccessDescription *accdsp = (struct AccessDescription *)inject_casn(
        &aiasp->self, 0);
      write_objid(&accdsp->accessMethod, id_ad_caIssuers);
      write_casn(&accdsp->accessLocation.url, 
        (uchar *)"rsync://roa-pki.bbn.com/home/testdir", 36);
      }
    else   // can copy it
      {
      extp = makeExtension(extsp, id_pkix_authorityInfoAccess);
      if (!(iextp = findExtension(iextsp, id_pkix_authorityInfoAccess)))
        fatal(4, "authorityInfoAccess");
      copy_casn(&extp->self, &iextp->self);
      }
    }
/*
  IF this is a root, use the subject's subjectKeyId field as a source
  ELSE  IF the issuer's cert has no subjectKeyId field, error
  ELSE use the issuer's subjKeyId filed as the source
  Get or make subject's authKey Id extension
  Copy the source  into subject's authKeyId
*/
  if (!issuerkeyfile) iextp = extp;
  else if (!(iextp = findExtension(&issuer.toBeSigned.extensions,
        id_subjectKeyIdentifier))) fatal(4, "subjectKeyIdentifier");
  extp = makeExtension(&ctftbsp->extensions, id_authKeyId);
  copy_casn(&extp->extnValue.authKeyId.keyIdentifier,
    &iextp->extnValue.subjectKeyIdentifier);
      // do IP addresses
  char *a;
  if (issuerkeyfile)
    {
    if (explicitIPAS >= 0) // no extension if explicitIPAS < 0
      extp = makeExtension(&ctftbsp->extensions, id_pe_ipAddrBlock);
    iextp = findExtension(&issuer.toBeSigned.extensions, id_pe_ipAddrBlock);
    if (!ee)
      {
      int numfam = 0;
      copy_casn(&extp->critical, &iextp->critical);
      clear_casn(&extp->extnValue.ipAddressBlock.self);
      struct IPAddressFamilyA *ifamp;
      for (ifamp = (struct IPAddressFamilyA *)member_casn(
        &iextp->extnValue.ipAddressBlock.self, 0); ifamp;
        ifamp =(struct IPAddressFamilyA *)next_of(&ifamp->self))
        {
        if (read_family(&a, ifamp) < 0) fatal(7, (char *)0);
        if (!filein) fprintf(stdout, a);
        if (!numfam) copy_casn(&extp->extnID, &iextp->extnID);
        struct IPAddressFamilyA *famp = (struct IPAddressFamilyA *)inject_casn(
          &extp->extnValue.ipAddressBlock.self, numfam++);
        copy_casn(&famp->addressFamily, &ifamp->addressFamily);
        if (!write_family(famp, filein))
          {
          eject_casn(&extp->extnValue.ipAddressBlock.self, --numfam);
          }
        }
      }
      // if making EE cert to sign ROA or manifest, inherit
    else if (!explicitIPAS)  
      inheritIPAddresses(extp, iextp);
      // else copy issuer's IP addresses
    else if (explicitIPAS > 0) copy_casn(&extp->self, &iextp->self);
      // if not a ROA EE, get AS num extension
    if (!strchr(subjfile, (int)'R'))  // not for ROAs
      {
      iextp = findExtension(&issuer.toBeSigned.extensions, id_pe_autonomousSysNum);
      extp = makeExtension(&ctftbsp->extensions, id_pe_autonomousSysNum);
      if (!ee)  // get numbers from input file
        {
        copy_casn(&extp->critical, &iextp->critical);
        struct ASNum *iasNump = &iextp->extnValue.autonomousSysNum;
        char *a;
        read_ASNums(&a, iasNump);
        if (!filein)
          {
          fprintf(stdout, a);
          fprintf(stdout, "What AS numbers?\n");
          }
        struct ASNum *asNump = &extp->extnValue.autonomousSysNum;
        write_ASNums(asNump);
        }
      else if (strchr(subjfile, (int)'M')) // for signing manifest
        write_casn(&extp->extnValue.autonomousSysNum.asnum.inherit, (uchar *)
          "", 0);
      else copy_casn(&extp->self, &iextp->self);
      }
      // subjectInfoAccess
    iextp = findExtension(&issuer.toBeSigned.extensions, id_pe_subjectInfoAccess);
    extp = makeExtension(extsp, id_pe_subjectInfoAccess);
    check_access_methods(iextp);
    copy_casn(&extp->self, &iextp->self);
    if (ee)  // change it for an EE cert
      {  // cut down to only 1 AccessDescription
      eject_casn(&extp->extnValue.subjectInfoAccess.self, 1);
      struct AccessDescription *accDesp = (struct AccessDescription *)
        member_casn(&extp->extnValue.subjectInfoAccess.self, 0);
      if (!accDesp) fatal(4, "SubjectInfoAccess");
        // force the accessMethod for an EE cert
      write_objid(&accDesp->accessMethod, id_ad_signedObject);
      }
    }
  else   // root
    {
    if (!(iextp = findExtension(extsp, id_pe_subjectInfoAccess)))
        fatal(4, "subjectInfoAccess");
    check_access_methods(iextp);
    }
  setSignature(&cert, (issuerkeyfile)? issuerkeyfile: subjkeyfile, bad);
  if (put_casn_file(&cert.self, subjfile, 0) < 0) fatal(2, subjfile);
  int siz = dump_size(&cert.self);
  char *rawp = (char *)calloc(1, siz + 4);
  siz = dump_casn(&cert.self, rawp);
  for (c = subjfile; *c && *c != '.'; c++);
  strcpy(c, ".raw");
  int fd = open(subjfile, (O_WRONLY | O_CREAT | O_TRUNC), (S_IRWXU));
  if (fd < 0) fatal(6, subjfile);
  if (write(fd, rawp, siz) < 0) perror(subjfile);
  close(fd);
  free(rawp);
  fatal(0, subjfile);
  return 0;
  }
