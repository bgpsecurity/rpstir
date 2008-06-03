/* $Id: make_roa.c 453 2008-07-25 15:30:40Z cgardiner $ */

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
 * Contributor(s):  Charles iW. Gardiner
 *
 * ***** END LICENSE BLOCK ***** */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <cryptlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <certificate.h>
#include <extensions.h>
#include <roa.h>

char *msgs[] =
  {
  "Finished %s OK\n",
  "Usage: ROAname\n",
  "Can't read %s\n",     // 2
  "Can't find %s extension in certificate\n",
  "Error writing %s\n",    // 4
  "Can't find extension %s\n",
  "Can't find ASNum[%d]\n",    // 6
  };

char certname[80], roaname[80];

void fatal(int err, char *param)
  {
  fprintf(stderr, msgs[err], param);
  exit(err);
  }

static long getASNum(struct Certificate *certp, long index)
  {
  struct Extensions *extsp = &certp->toBeSigned.extensions;
  struct Extension *extp;
  long ansr, starter = index;
  for (extp = (struct Extension *)member_casn(&extsp->self, 0); 
    extsp && diff_objid(&extp->extnID, id_pe_autonomousSysNum);
    extp = (struct Extension *) next_of(&extp->self));
  if (!extp) fatal(5, id_pe_autonomousSysNum);
  struct ASNumberOrRangeA *asnump;
  for (asnump = (struct ASNumberOrRangeA *)member_casn(
    &extp->extnValue.autonomousSysNum.asnum.asNumbersOrRanges.self, 0); asnump; 
    asnump = (struct ASNumberOrRangeA *)next_of(&asnump->self))
    {
    if (vsize_casn(&asnump->num))
      {
      if (!starter--)
        {
        read_casn_num(&asnump->num, &ansr);
        break;
        }
      }
    else
      {
      long min, max, tmp;
      read_casn_num(&asnump->range.min, &min);
      read_casn_num(&asnump->range.max, &max);
      tmp = max + 1 - min;
      if (starter >= tmp) starter -= tmp;
      else 
        {
        ansr = min + starter;
        starter = -1;
        break;
        }
      }
    }
  if (starter >= 0) fatal(6, (char *)index);
  return ansr;
  }

static void getIPAddresses(struct ROAIPAddrBlocks *roaipp, struct IpAddrBlock *ipap,
  long index)
  {
  int numfams = 0;
  struct IPAddressFamilyA *ipFamp;
  for (ipFamp = (struct IPAddressFamilyA *)member_casn(&ipap->self, 0); ipFamp;
    ipFamp = (struct IPAddressFamilyA *)next_of(&ipFamp->self))
    {
    struct ROAIPAddressFamily *roafp = (struct ROAIPAddressFamily *)inject_casn(
      &roaipp->self, numfams++);
    copy_casn(&roafp->addressFamily, &ipFamp->addressFamily);
      // assume only 1 IPAddressOrRange in cert
    struct IPAddressOrRangeA *ipaorrp = (struct IPAddressOrRangeA *)member_casn(
      &ipFamp->ipAddressChoice.  addressesOrRanges.self, 0);
    struct ROAIPAddress *roaipa = (struct ROAIPAddress *)inject_casn(
      &roafp->addresses.self, 0); 
    uchar *addrp;
    int lth = readvsize_casn(&ipaorrp->addressPrefix, &addrp);
    if (addrp[0] > 1) addrp[0] -= 2;
    else
      {
      addrp = (uchar *)realloc(addrp, ++lth);
      addrp[0] += 6;
      addrp[lth - 1] = 0;
      }
    write_casn(&roaipa->address, addrp, lth);
    }
  }

static int signROA(struct ROA* roa, char *keyfilename, int bad)
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
  else if ((ansr = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, 
    keyfilename, CRYPT_KEYOPT_READONLY)) != 0) msg = "opening key set";
  else if ((ansr = cryptGetPrivateKey(cryptKeyset, &sigKeyContext, CRYPT_KEYID_NAME, 
    "label", "password")) != 0) msg = "getting key";
  else if ((ansr = cryptCreateSignature(NULL, 0, &signatureLength, sigKeyContext, 
    hashContext)) != 0) msg = "signing";
  else     // sign it
    {
    signature = (uchar *)calloc(1, signatureLength +20);
    if ((ansr = cryptCreateSignature(signature, 200, &signatureLength, sigKeyContext,
      hashContext)) != 0) msg = "signing";
    else if ((ansr = cryptCheckSignature(signature, signatureLength, sigKeyContext, 
      hashContext))
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
    if (bad)
      {
      uchar *sig;
      int siz = readvsize_casn(&sigInfop->signature, &sig);
      sig[0]++;
      write_casn(&sigInfop->signature, sig, siz);
      free(sig);
      }
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

int main (int argc, char **argv)
  {
  struct ROA roa;
  ROA(&roa, (ushort)0);
  struct Certificate cert;
  Certificate(&cert, (ushort)0);
  if (argc < 2) fatal(1, (char *)0);
  strcpy(roaname, argv[1]);
  char *c;
  for (c = roaname; *c && *c != '.'; c++);
  long asnum, index;
  sscanf(&c[-1], "%ld", &index);
  index--;  // change to cardinal #
  if (!*c) strcpy(c, ".roa");
  strcpy(certname, argv[1]);
  certname[0] = 'C';
  c = &certname[c - roaname - 1];  // cut off last digit
  strcpy(c, "E.cer");
  if (get_casn_file(&cert.self, certname, 0) < 0) fatal(2, certname);
  write_objid(&roa.contentType, id_signedData);
  struct SignedData *sgdp = &roa.content.signedData;
  write_casn_num(&sgdp->version.self, 3);
  struct AlgorithmIdentifier *algidp = (struct AlgorithmIdentifier *)
    inject_casn(&sgdp->digestAlgorithms.self, 0);
  write_objid(&algidp->algorithm, id_sha256);
  write_casn(&algidp->parameters.sha256, (uchar *)"", 0);
  
  struct Certificate *ecertp = (struct Certificate *)inject_casn(
    &sgdp->certificates.self, 0);
  copy_casn(&ecertp->self, &cert.self);

  asnum = getASNum(ecertp, index);  
  write_objid(&sgdp->encapContentInfo.eContentType, id_routeOriginAttestation);
  struct RouteOriginAttestation *roap = &sgdp->encapContentInfo.eContent.roa;
  write_casn_num(&roap->asID, asnum);
  struct Extension *extp;
  for (extp = (struct Extension *)member_casn(&cert.toBeSigned.extensions.self, 0);
    extp && diff_objid(&extp->extnID, id_pe_ipAddrBlock);
    extp = (struct Extension *)next_of(&extp->self));
  if (!extp) fatal(3, "IP Address Block");
  getIPAddresses(&roap->ipAddrBlocks, &extp->extnValue.ipAddressBlock, index);
  for (c = certname; *c && *c != '.'; c++);
  strcpy(c, ".p15");
  signROA(&roa, certname, argc - 2);
  if (put_casn_file(&roa.self, roaname, 0) < 0) fatal(4, roaname);
  for (c = roaname; *c != '.'; c++);
  strcpy(c, ".raw");
  int fd = open(roaname, (O_WRONLY | O_CREAT | O_TRUNC), (S_IRWXU));
  if (fd < 0) fatal(4, roaname);
  int siz = dump_size(&roa.self);
  char *rawp = (char *)calloc(1, siz + 4);
  siz = dump_casn(&roa.self, rawp);
  if (write(fd, rawp, siz) < 0) perror(roaname);
  close(fd);
  free(rawp);
  fatal(0, roaname);
  return 0;
  }  
