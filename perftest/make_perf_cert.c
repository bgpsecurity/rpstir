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
#include <crlv2.h>
#include <keyfile.h>
#include <casn.h>
#include <asn.h>
#include <time.h>

char *msgs [] =
    {
    "Finished %s OK\n",
    "Couldn't open %s\n",
    "Invalid name %s\n",      // 2
    "Usage: subjectname howmany [ASnum]\n",
    "Issuer cert has no %s extension\n",              // 4
    "Signing failed in %s\n",
    "Error opening %s\n",                // 6
    "Error reading IP Address Family\n",
    "Error padding prefix %s. Try again\n",       // 8
    "Invalid cert name %s\n",
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

static int setSignature(struct casn *tbhash, struct casn *newsignature,
  char *keyfile, int bad)
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

  if ((sign_lth = size_casn(tbhash)) < 0) fatal(5, "sizing");
  signstring = (uchar *)calloc(1, sign_lth);
  sign_lth = encode_casn(tbhash, signstring);
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
      if ((ansr = write_casn_bits(newsignature, signstring, ansr, 0)) < 0)
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
  if (argc < 3 || argc > 4) fatal(3, "");
  int ee = 0, explicitIPAS = 0x0;
  struct Certificate cert;
  struct Certificate issuer;
  Certificate(&cert, (ushort)0);
  struct CertificateToBeSigned *ctftbsp = &cert.toBeSigned;
  Certificate(&issuer, (ushort)0);
  char *c, *subjkeyfile = "C1.p15", 
      *subjfile, 
      *issuerfile = (char *)0,
      *issuerkeyfile = (char *)0, 
      subjname[20],
      inherit = 0;
  for (c = &argv[1][1]; *c && ((*c >= '0' && *c <= '9') || *c == '.'); c++);
  if (*c && *c != 'M' && *c != 'R') fatal(10, argv[1]);
  if (*c) ee = 1;
  subjfile = (char *)calloc(1, strlen(argv[1]) + 8);
  subjkeyfile = (char *)calloc(1, strlen(argv[1]) + 8);
  int numcerts;
  sscanf(argv[2], "%d", &numcerts);
  long snum = 1;
         // get keyfile for subject public key
  int dots = 0, rir, nir = -1, isp = -1;
  dots = sscanf(argv[1], "C%d.%d.%d", &rir, &nir, &isp) - 1;
  if (rir > 9 || nir > 99999 || isp > 999) fatal(2, argv[1]);
  if (!dots) sprintf(subjname, "C%d", rir);
  else if (dots == 1) sprintf(subjname, "C%d.%05d", rir, nir);
  else if (dots == 2) sprintf(subjname, "C%d.%05d.%03d", rir, nir, isp);
  else fatal(9, argv[1]);
  issuerfile = (char *)calloc(1, strlen(subjname + 8));
  char *a = argv[1];        // get the issuer file
  for (a++; (*a >= '0' && *a <= '9') || *a == '.'; a++);
  if (!*a)        // if not EE, cut off last field for issuer
    {
    int lth;
    if (dots == 0) lth = 1;
    else if (dots == 1) lth = 2;
    else if (dots == 2) lth = 8;
    else fatal(9, argv[1]);
    strncpy(issuerfile, subjname, lth);
    }
  else // otherwise a is at non-digit
    {
    inherit = *a;
    strcpy(issuerfile, subjname);
    strcat(subjname, a);
    }
  strcat(issuerfile, ".cer");
  if (get_casn_file(&issuer.self, issuerfile, 0) < 0) fatal(1, issuerfile);
  issuerkeyfile = "C1.p15";
  if (dots == 0) sscanf(subjname, "C%ld", &snum);
  else if (dots == 1) sscanf(&subjname[2], ".%ld", &snum);
  else sscanf(&subjname[8], ".%ld", &snum);
  if (inherit) numcerts = 1;
  else sscanf(argv[2], "%d", &numcerts);
  if ((dots == 0 && rir + numcerts - 1 > 9) ||
    (dots == 1 && nir + numcerts - 1 > 99999) ||
    (dots == 2 && isp + numcerts - 1 > 999)) fatal(2, argv[1]); 
  int numcert;
  for (numcert = 0; numcert < numcerts; numcert++, snum++)
    {
    if (numcerts > 1)  // don't need to do this for first
      {              // and besides it would clobber appended R or M 
      if (dots == 0) subjname[1] = snum + '0';
      else if (dots == 1) sprintf(&subjname[3], "%05ld", snum);
      else if (dots == 2) sprintf(&subjname[9], "%03ld", snum);
      }
    strcat(strcpy(subjfile, subjname), ".cer");
    // start filling subject cert
    clear_casn(&cert.self);
    write_casn_num(&ctftbsp->version.self, 2);
    if (inherit == 'M') snum += 0x100000;
    if (inherit == 'R') snum += 0x200000;
    write_casn_num(&ctftbsp->serialNumber, (long)snum);
    copy_casn(&cert.algorithm.self, &issuer.toBeSigned.signature.self);
    copy_casn(&ctftbsp->signature.self, &issuer.toBeSigned.signature.self);
    copy_casn(&ctftbsp->issuer.self, &issuer.toBeSigned.subject.self);
        // use parent's public key
    copy_casn(&ctftbsp->subjectPublicKeyInfo.self, 
      &issuer.toBeSigned.subjectPublicKeyInfo.self);
    set_name(&ctftbsp->subject.rDNSequence, subjname);

    long now = time((time_t *)0);
    write_casn_time(&ctftbsp->validity.notBefore.utcTime, now);
      // make it 1 year
    write_casn_time(&ctftbsp->validity.notAfter.utcTime, now +
      (365 * 24 * 3600));
  
    struct Extensions *extsp = &ctftbsp->extensions, *iextsp;
    iextsp = &issuer.toBeSigned.extensions;
    struct Extension *extp, *iextp;
         // make subjectKeyIdentifier first
    extp = makeExtension(extsp, id_subjectKeyIdentifier);
    uchar ski[20];
    memset(ski, 0x20, 20);
    strncpy((char *)ski, subjname, strlen(subjname));
    write_casn(&extp->extnValue.subjectKeyIdentifier, ski, 20);
    // key usage
    extp = makeExtension(extsp, id_keyUsage);
    if (!(iextp = findExtension(iextsp, id_keyUsage))) fatal(4, "key usage");
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
    extp = makeExtension(extsp, id_pkix_authorityInfoAccess);
    if (!(iextp = findExtension(iextsp, id_pkix_authorityInfoAccess)))
      fatal(4, "authorityInfoAccess");
    copy_casn(&extp->self, &iextp->self);
    if (!(iextp = findExtension(&issuer.toBeSigned.extensions,
          id_subjectKeyIdentifier))) fatal(4, "subjectKeyIdentifier");
    extp = makeExtension(&ctftbsp->extensions, id_authKeyId);
    copy_casn(&extp->extnValue.authKeyId.keyIdentifier,
      &iextp->extnValue.subjectKeyIdentifier);
        // do IP addresses
  
    if (explicitIPAS >= 0) // no extension if explicitIPAS < 0
      extp = makeExtension(&ctftbsp->extensions, id_pe_ipAddrBlock);
    iextp = findExtension(&issuer.toBeSigned.extensions, id_pe_ipAddrBlock);
    if (!ee)
      {
      copy_casn(&extp->critical, &iextp->critical);
      struct IPAddressFamilyA *famp = (struct IPAddressFamilyA *)inject_casn(
          &extp->extnValue.ipAddressBlock.self, 0);
      uchar fam[2];
      fam[0] = 0;
      fam[1] = 1;
      write_casn(&famp->addressFamily, fam, 2);
      struct IPAddressOrRangeA *ipaorp;
      int numaddrs, addrnum, addrlth;
      uchar startaddr[5], *up, incr;
      memset(startaddr, 0, 5);
      if (dots == 0)
        {
        numaddrs = 1024;
        startaddr[0] = 0x00;
        startaddr[1] = 0x08;
        startaddr[2] = 0x0;
        addrlth = 4;
        incr = 0x1;
        up = &startaddr[3];
        }
      else 
        {
        numaddrs = (dots == 1)? 256: 1;
        startaddr[0] = 0x00;
        startaddr[1] = 0x08;
        startaddr[2] = 0x0;
        startaddr[3] = 0;
        startaddr[4] = 0;
        addrlth = 5;
        incr = 1;
        up = &startaddr[4];
        }
         
      for (addrnum = 0; addrnum < numaddrs; addrnum++)
        {
        ipaorp = (struct IPAddressOrRangeA *)inject_casn(&famp->ipAddressChoice.
          addressesOrRanges.self, addrnum);
        write_casn(&ipaorp->addressPrefix, startaddr, addrlth);
        *up += incr;    // increment address block
        if (!*up) 
          {
          up[-1]++;
          if (up > &startaddr[3] && !up[-1]) up[-2]++;
          } 
        }
      }
      // if making EE cert to sign ROA or manifest, inherit
    else inheritIPAddresses(extp, iextp);
      // if not a ROA EE, get AS num extension
    if (!strchr(subjfile, (int)'R'))  // not for ROAs
      {
      iextp = findExtension(&issuer.toBeSigned.extensions, 
        id_pe_autonomousSysNum);
      extp = makeExtension(&ctftbsp->extensions, id_pe_autonomousSysNum);
      if (!ee)  // get number from subject file name
        {
        int lev2, lev3, lev4, asnum;
        if (dots == 0) sscanf(subjname, "C%d", &asnum);
        else if (dots == 1) 
          {
          sscanf(subjname, "C%d.%d", &lev2, &lev3);
          asnum = (lev2 * 100000) + lev3;
          }
        else 
          {
          sscanf(subjname, "C%d.%d.%d", &lev2, &lev3, &lev4);
          asnum = (lev2 * 100000000) + (lev3 * 1000) + lev4;
          }
        copy_casn(&extp->critical, &iextp->critical);
        struct ASNumberOrRangeA *asnorp = (struct ASNumberOrRangeA *)
          inject_casn(&extp->extnValue.autonomousSysNum.asnum.
            asNumbersOrRanges.self, 0);
        write_casn_num(&asnorp->num, asnum);
        }
      else if (strchr(subjfile, (int)'M')) // for signing manifest
        write_casn(&extp->extnValue.autonomousSysNum.asnum.inherit, (uchar *)
          "", 0);
      else copy_casn(&extp->self, &iextp->self);
      }
      // subjectInfoAccess
    iextp = findExtension(&issuer.toBeSigned.extensions, 
      id_pe_subjectInfoAccess);
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
    setSignature(&cert.toBeSigned.self, &cert.signature, issuerkeyfile, 0);
    if (put_casn_file(&cert.self, subjfile, 0) < 0) fatal(2, subjfile);
    int siz = dump_size(&cert.self);
    char *rawp = (char *)calloc(1, siz + 4);
    siz = dump_casn(&cert.self, rawp);
    strcat(strcpy(subjfile, subjname), ".raw");
    int fd = open(subjfile, (O_WRONLY | O_CREAT | O_TRUNC), (S_IRWXU));
    if (fd < 0) fatal(6, subjfile);
    if (write(fd, rawp, siz) < 0) perror(subjfile);
    close(fd);
    free(rawp);
    if (!ee)
      {
      struct CertificateRevocationList crl;
      CertificateRevocationList(&crl, (ushort)0);
      struct CertificateRevocationListToBeSigned *crltbsp =
        &crl.toBeSigned;
      write_casn_num(&crltbsp->version.self, 1);
      copy_casn(&crltbsp->signature.self, &ctftbsp->signature.self);
      copy_casn(&crltbsp->issuer.self, &ctftbsp->subject.self);
      write_casn_time(&crltbsp->lastUpdate.utcTime, now);
      write_casn_time(&crltbsp->nextUpdate.utcTime, now + (30 * 24 * 3600));
      struct CRLEntry *crlEntryp = (struct CRLEntry *)inject_casn(
        &crltbsp->revokedCertificates.self, 0);
      write_casn_num(&crlEntryp->userCertificate, 1);
      write_casn_time(&crlEntryp->revocationDate.utcTime, now - (10 * 24 * 3600));
      copy_casn(&crl.algorithm.self, &cert.algorithm.self);
      setSignature(&crl.toBeSigned.self, &crl.signature, issuerkeyfile, 0);
      char *crlfile = (char *)calloc(1, strlen(subjfile) + 2);
      strcpy(crlfile, subjfile);
      crlfile[0] = 'L';
      strcpy(strchr(crlfile, 'r'), "crl");
      put_casn_file(&crl.self, crlfile, 0);
      siz = dump_size(&crl.self);
      rawp = (char *)calloc(1, siz + 4);
      siz = dump_casn(&crl.self, rawp);
      strcpy(strchr(crlfile, 'c'), "raw");
      int fd = open(crlfile, (O_WRONLY | O_CREAT | O_TRUNC), (S_IRWXU));
      if (fd < 0) fatal(6, crlfile);
      if (write(fd, rawp, siz) < 0) perror(crlfile);
      close(fd);
      free(crlfile);
      free(rawp);
      }
    }
  fatal(0, subjfile);
  return 0;
  }
