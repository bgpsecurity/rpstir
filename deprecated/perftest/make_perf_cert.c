/* $Id: make_cert.c 453 2008-05-28 15:30:40Z cgardiner $ */

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

extern char *signCMS(struct ROA *, char *, int);

char *msgs [] =
    {
    "Finished %s OK\n",
    "Couldn't open %s\n",
    "Invalid name %s\n",      // 2
    "Usage: subjectname howmany [num prefixes]\n",
    "Issuer cert has no %s extension\n",              // 4
    "Signing failed in %s\n",
    "Error opening %s\n",                // 6
    "Error reading IP Address Family\n",
    "Error inserting manifest FileAndHash\n",       // 8
    "Invalid cert name %s\n",
    "Invalid cert name %s\n",             // 10
    "%d prefixes is too many\n",
    "Error in CA %s extension\n",      // 12
    "Invalid parameter %s\n",
    "Error encoding %s\n",             // 14
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

static int gen_hash(uchar *inbufp, int bsize, uchar *outbufp)
  { 
  CRYPT_CONTEXT hashContext;
  uchar hash[40];
  int ansr;

  memset(hash, 0, 40);
  cryptInit();
  cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2);
  cryptEncrypt(hashContext, inbufp, bsize);
  cryptEncrypt(hashContext, inbufp, 0);
  cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ansr);
  cryptDestroyContext(hashContext);
  cryptEnd();
  memcpy(outbufp, hash, ansr);
  return ansr;
  }

static void add_to_manifest(struct FileListInManifest *flimp, char *curr_file,
    struct casn *casnp)
  {
  int num = num_items(&flimp->self), siz;
  struct FileAndHash *fahp;
  if (!(fahp = (struct FileAndHash *)inject_casn(&flimp->self, num))) 
    fatal(8, "");
  if ((siz = size_casn(casnp)) < 0) fatal(14, curr_file);
  uchar *buf = (uchar *)calloc(1, siz);
  encode_casn(casnp, buf);
  uchar hash[40];
  int hsiz = gen_hash(buf, siz, hash);
  write_casn(&fahp->file, (uchar *)curr_file, strlen(curr_file));
  write_casn_bits(&fahp->hash, hash, hsiz, 0);
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

// copy the ip addr blocks over into the roa
static void getIPAddresses(struct ROAIPAddrBlocks *roaipp,
   struct IpAddrBlock *ipap, int v4maxLen, int v6maxLen, int v4choice,
   int v6choice)
  {
  int numfams = 0;
  struct IPAddressFamilyA *ipFamp;
    // copy all families from the cert (ipap) to the ROA (roaipp)
  for (ipFamp = (struct IPAddressFamilyA *)member_casn(&ipap->self, 0);
       ipFamp;
       ipFamp = (struct IPAddressFamilyA *)next_of(&ipFamp->self))
    {

    // insert a slot for the new family
    struct ROAIPAddressFamily *roafp = (struct ROAIPAddressFamily *)
      inject_casn(&roaipp->self, numfams++);

    // copy over the family ID (v4 or v6)
    copy_casn(&roafp->addressFamily, &ipFamp->addressFamily);
    uchar fam[2];
    read_casn(&ipFamp->addressFamily, fam);

    struct IPAddressOrRangeA *ipaorrp;
    int choice = (fam[1] == 1)? v4choice: v6choice; // specified choice?
    int numAddr = 0, numwritten = 0;
    for (ipaorrp = (struct IPAddressOrRangeA *) member_casn(
      &ipFamp->ipAddressChoice.addressesOrRanges.self, 0);
      ipaorrp; numAddr++,
      ipaorrp = (struct IPAddressOrRangeA *)next_of(&ipaorrp->self))
      {
      if (choice >= 0 && choice != numAddr) continue; // skip others
      // insert the casn for the ip addr
      struct ROAIPAddress *roaipa = (struct ROAIPAddress *) inject_casn(
        &roafp->addresses.self, numwritten++);
      // if cert has a range, give up
      if (size_casn(&ipaorrp->addressRange.self)) fatal(1, "");
      // otherwise copy the prefix
      copy_casn(&roaipa->address, &ipaorrp->addressPrefix);
      if (!numAddr) // only on first
        {
        if (fam[1] == 1 && v4maxLen > 0)
          write_casn_num(&roaipa->maxLength, (long)v4maxLen);
        if (fam[1] == 2 && v6maxLen > 0)
          write_casn_num(&roaipa->maxLength, (long)v6maxLen);
        }
      }
    }
  // all done
  return;
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
//  change this to a /* for debugging if signing doesn't work
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
//    put this */ back in to terminate commented out stuff
/*  then uncomment this
  uchar signstring[24];
  strcpy((uchar *)signstring, "This is a signature");
  write_casn_bits(newsignature, signstring, 20, 0);
  return 0;
down to here */
  }

static void fill_cert(char *subjname, struct Certificate *certp,
  struct Certificate *issuerp, int snum, char inherit, int dots, int numaddrs)
  {
  struct CertificateToBeSigned *ctftbsp = &certp->toBeSigned;
  write_casn_num(&ctftbsp->version.self, 2);
  if (inherit == 'M') snum += 0x100000;
  if (inherit == 'R') snum += 0x200000;
  write_casn_num(&ctftbsp->serialNumber, (long)snum);
  set_name(&ctftbsp->subject.rDNSequence, subjname);

  long now = time((time_t *)0);
  write_casn_time(&ctftbsp->validity.notBefore.utcTime, now);
    // make it 1 year
  write_casn_time(&ctftbsp->validity.notAfter.utcTime, now +
    (365 * 24 * 3600));

  struct Extensions *extsp = &ctftbsp->extensions, 
    *iextsp = &issuerp->toBeSigned.extensions;
  clear_casn(&ctftbsp->extensions.self);
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
  if (inherit)
    {
    write_casn(&extp->extnValue.keyUsage.self, (uchar *)"", 0);
    write_casn_bit(&extp->extnValue.keyUsage.digitalSignature, 1);
    }
  // basic constraints
  if (!inherit)
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
  if (!(iextp = findExtension(&issuerp->toBeSigned.extensions,
        id_subjectKeyIdentifier))) fatal(4, "subjectKeyIdentifier");
  extp = makeExtension(&ctftbsp->extensions, id_authKeyId);
  copy_casn(&extp->extnValue.authKeyId.keyIdentifier,
    &iextp->extnValue.subjectKeyIdentifier);
      // do IP addresses

  extp = makeExtension(&ctftbsp->extensions, id_pe_ipAddrBlock);
  iextp = findExtension(&issuerp->toBeSigned.extensions, id_pe_ipAddrBlock);
  if (!inherit)
    {
    copy_casn(&extp->critical, &iextp->critical);
    struct IPAddressFamilyA *famp = (struct IPAddressFamilyA *)inject_casn(
        &extp->extnValue.ipAddressBlock.self, 0);
    uchar fam[2];
    fam[0] = 0;
    fam[1] = 1;
    write_casn(&famp->addressFamily, fam, 2);
    struct IPAddressOrRangeA *ipaorp;
    int addrnum, addrlth;
    uchar startaddr[5], *up, incr;
    memset(startaddr, 0, 5);
    if (dots == 0)
      {
      startaddr[0] = 0x00;
      startaddr[1] = 0x08;
      startaddr[2] = 0;
      addrlth = 4;
      incr = 0x2;
      up = &startaddr[3];
      }
    else
      {
      startaddr[0] = 0x0;
      startaddr[1] = 0x08;
      startaddr[2] = 0x0;
      startaddr[3] = 0;
      startaddr[4] = 0;
      addrlth = 5;
      incr = 2;
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
  if (inherit != 'R')  // not for ROAs
    {
    iextp = findExtension(&issuerp->toBeSigned.extensions,
      id_pe_autonomousSysNum);
    extp = makeExtension(&ctftbsp->extensions, id_pe_autonomousSysNum);
    if (!inherit)  // get number from subject file name
      {
      int lev1, lev2, lev3, lonum, hinum;
      if (dots == 0) 
        {
        sscanf(subjname, "C%d", &lev1);
        lonum = lev1 *  100000000;
        hinum = lonum +  99999999;
        }
      else if (dots == 1)
	{
	sscanf(subjname, "C%d.%d", &lev1, &lev2);
	lonum = (lev1 * 100000000) + (lev2 * 1000);
        hinum = lonum + 999;
	}
      else
        {
	sscanf(subjname, "C%d.%d.%d", &lev1, &lev2, &lev3);
	lonum = (lev1 * 100000000) + (lev2 * 1000) + lev3;
	}
      copy_casn(&extp->critical, &iextp->critical);
      struct ASNumberOrRangeA *asnorp = (struct ASNumberOrRangeA *)
        inject_casn(&extp->extnValue.autonomousSysNum.asnum.
          asNumbersOrRanges.self, 0);
      if (dots < 2)
        {
        write_casn_num(&asnorp->range.min, lonum);
        write_casn_num(&asnorp->range.max, hinum);
        }
      else write_casn_num(&asnorp->num, lonum);
      }
    else if (inherit == 'M') // for signing manifest
      write_casn(&extp->extnValue.autonomousSysNum.asnum.inherit, (uchar *)
        "", 0);
    else copy_casn(&extp->self, &iextp->self);
    }
    // subjectInfoAccess
  iextp = findExtension(&issuerp->toBeSigned.extensions,
    id_pe_subjectInfoAccess);
  extp = makeExtension(extsp, id_pe_subjectInfoAccess);
  check_access_methods(iextp);
  copy_casn(&extp->self, &iextp->self);
  if (inherit)  // change it for an EE cert
    {  // cut down to only 1 AccessDescription
    eject_casn(&extp->extnValue.subjectInfoAccess.self, 1);
    struct AccessDescription *accDesp = (struct AccessDescription *)
      member_casn(&extp->extnValue.subjectInfoAccess.self, 0);
    if (!accDesp) fatal(4, "SubjectInfoAccess");
      // force the accessMethod for an EE cert
    write_objid(&accDesp->accessMethod, id_ad_signedObject);
    }
  }

static void write_cert_and_raw(char *subjfile, struct Certificate *certp)
  {
  int siz;
  char *rawp;
//  fprintf(stderr, "Writing %s\n", subjfile);
  if (put_casn_file(&certp->self, subjfile, 0) < 0) fatal(2, subjfile);
  siz = dump_size(&certp->self);
  rawp = (char *)calloc(1, siz + 4);
  siz = dump_casn(&certp->self, rawp);
  strcpy(&subjfile[strlen(subjfile) - 4], ".raw");
  int fd = open(subjfile, (O_WRONLY | O_CREAT | O_TRUNC), (S_IRWXU));
  if (fd < 0) fatal(6, subjfile);
  if (write(fd, rawp, siz) < 0) perror(subjfile);
  close(fd);
  free(rawp);
  }

static void write_roa_and_raw(char *subjfile, struct ROA *roap)
  {
  int siz;
  char *rawp;
//  fprintf(stderr, "Writing %s\n", subjfile);
  if (put_casn_file(&roap->self, subjfile, 0) < 0) fatal(2, subjfile);
  siz = dump_size(&roap->self);
  rawp = (char *)calloc(1, siz + 4);
  siz = dump_casn(&roap->self, rawp);
  strcpy(&subjfile[strlen(subjfile) - 4], ".raw");
  int fd = open(subjfile, (O_WRONLY | O_CREAT | O_TRUNC), (S_IRWXU));
  if (fd < 0) fatal(6, subjfile);
  if (write(fd, rawp, siz) < 0) perror(subjfile);
  close(fd);
  free(rawp);
  }

int main(int argc, char **argv)
  {
/*
Notes:
1. We should be in the directory of the issuing CA
2. argv[1] specifies the name of the first subordinate CA to be created
   argv[2] specifies the number of CAs to be made.
   argv[3] specifies the number of prefixes to put in each CA cert
3. All the certs created plus the issuer's CRL and, for all but the top CA
   ("C") two end-entity certs are created in this directory
4. The cert of the issuing CA is one directory above, except when the issuer
   is C

Procedure:
1. Get the issuer's name from argv[1]
   Get its cert
   Prepare subject cert
   Prepare roa and either prepare the manifest or read it in
2  IF this is forst time
     Make two end-entity certs and put them into ROA and manifest
3.   Create and write a CRL for this CA, adding name to the manifest
   ELSE read in the existing manifest
4. FOR all the quantity specified, create and write certs, adding
    their names to the manifest
5. IF it's a "first time", fill in the ROA details, sign it and write it
6. Sign the manifest and write it
*/
  if (argc < 3 || argc > 13 || ((argc - 1) %3) != 0  ) fatal(3, "");
  struct Certificate cert;
  struct Certificate issuer;
  Certificate(&cert, (ushort)0);
  Certificate(&issuer, (ushort)0);
  char *c, issuerkeyfile[40],
      subjfile[40],
      *issuerfile = (char *)0,
      subjname[20], dirname[40];
  char roafile[40], manifestfile[40];
  int numsteps = argc - 1;
  int dots;
  for (dots = 0, c = argv[1]; *c; c++) if (*c == '.') dots++;
  struct casn casn;
  simple_constructor(&casn, (ushort)0, ASN_UTCTIME);
  long now = time((time_t *)0);
  write_casn_time(&casn, now);
  uchar tbuf[20];
  read_casn(&casn, tbuf);
  if (dots < 3) fprintf(stderr, "Start %s\n", (char *)tbuf);
  int curr_step;
  for (curr_step = 0; curr_step < numsteps; curr_step += 3)
    {
    for (c = &argv[curr_step + 1][1]; 
      *c && ((*c >= '0' && *c <= '9') || *c == '.'); c++);
    if (*c) fatal(10, argv[curr_step + 1]);
    int numcerts, numaddrs = 1;
    sscanf(argv[curr_step + 2], "%d", &numcerts);
    if (argc > 3) sscanf(argv[curr_step + 3], "%d", &numaddrs);
    int dots = 0, rir, nir = -1, isp = -1;
    dots = sscanf(argv[curr_step + 1], "C%d.%d.%d", &rir, &nir, &isp) - 1;
    if ((dots == 0 && rir + numcerts - 1 > 9) ||
      (dots == 1 && nir + numcerts - 1 > 99999) ||
      (dots == 2 && isp + numcerts - 1 > 999)) fatal(2, argv[curr_step + 1]);
    if (dots == 2 && !strrchr(argv[curr_step + 1], '.')[1]) dots = 3;
    int addrlimits[4] = {1023, 256, 8, 1};
    if (numaddrs > addrlimits[dots]) fatal(11, (char *)numaddrs);
    memset(dirname, 0, sizeof(dirname));
    if (!dots) dirname[0] = 0;
    else if (dots == 1) sprintf(dirname, "%d", rir);  
    else if (dots == 2) sprintf(dirname, "%d/%05d", rir, nir);  
    else if (dots == 3) sprintf(dirname, "%d/%05d/%03d", rir, nir, isp);  
    if (dots) printf("cd+++++++ %s\n", dirname);
    memset(issuerkeyfile, 0, sizeof(issuerkeyfile));
    int i;
    for (i = 0; i < dots; i++) strcat(issuerkeyfile, "../");
    strcat(issuerkeyfile, "C.p15");
                                    /* step 1 */
    memset(subjname, 0, sizeof(subjname));
    memset(subjfile, 0, sizeof(subjfile));
    if (!dots) 
      {
      issuerfile = "C.cer";
      strcpy(subjname, argv[curr_step + 1]);
      }
    else
        {
        int lth = 2;  // if dots == 1
        if (dots == 2) lth = 8;
        else if (dots == 3) lth = 12;
        strncpy(subjname, argv[curr_step + 1], lth);
        issuerfile = (char *)calloc(1, lth + 8);
        strcpy(issuerfile, "../");
        strncpy(&issuerfile[3], subjname, lth);
        strcat(issuerfile, ".cer");
        }
          // get issuer file
    if (get_casn_file(&issuer.self, issuerfile, 0) < 0) fatal(1, issuerfile);
        // set up subject
    struct CertificateToBeSigned *ctftbsp = &cert.toBeSigned;
    copy_casn(&cert.algorithm.self, &issuer.toBeSigned.signature.self);
    copy_casn(&ctftbsp->signature.self, &issuer.toBeSigned.signature.self);
    copy_casn(&ctftbsp->issuer.self, &issuer.toBeSigned.subject.self);
        // use parent's public key
    copy_casn(&ctftbsp->subjectPublicKeyInfo.self,
      &issuer.toBeSigned.subjectPublicKeyInfo.self);
  
      // make ROA and manifest
    int first_time = 0;
    if ((!dots && rir == 1) || (dots == 1 && nir == 1) || (dots == 2 && isp == 1)
      || dots == 3) first_time = 1;
    if (!dots) strcpy(roafile, "R.roa");
    else strcat(strcpy(roafile, subjname), ".roa");
    roafile[0] = 'R';
    struct ROA roa, manifest;
    ROA(&roa, (ushort)0);
    ROA(&manifest, (ushort)0);
    if (!dots) strcpy(manifestfile, "M.man");
    else strcat(strcpy(manifestfile, subjname), ".man");
    manifestfile[0] = 'M';
    struct SignedData *sgdp;
    struct Manifest *manp = &manifest.content.signedData.encapContentInfo.
      eContent.manifest;
    long snum = 1;
    if (first_time)
      {
      write_objid(&roa.contentType, id_signedData);
      sgdp = &roa.content.signedData;
      write_casn_num(&sgdp->version.self, 3);
      struct AlgorithmIdentifier *algidp = (struct AlgorithmIdentifier *)
        inject_casn(&sgdp->digestAlgorithms.self, 0);
      write_objid(&algidp->algorithm, id_sha256);
      write_casn(&algidp->parameters.sha256, (uchar *)"", 0);
      write_objid(&sgdp->encapContentInfo.eContentType, id_routeOriginAttestation);
  //    write_casn_num( &(roap->version.self), roaVersion);
        // end of basic roa setup
      write_objid(&manifest.contentType, id_signedData);
      sgdp = &manifest.content.signedData;
      write_casn_num(&sgdp->version.self, 3);
      algidp = (struct AlgorithmIdentifier *)
        inject_casn(&sgdp->digestAlgorithms.self, 0);
      write_objid(&algidp->algorithm, id_sha256);
      write_casn(&algidp->parameters.sha256, (uchar *)"", 0);
      write_objid(&sgdp->encapContentInfo.eContentType, id_roa_pki_manifest);
      write_casn_num(&manp->manifestNumber, (long)index);
      now = time((time_t *)0);
      write_casn_time(&manp->thisUpdate, now);
      write_casn_time(&manp->nextUpdate, (now + (30 * 24 * 3600)));
      write_objid(&manp->fileHashAlg, id_sha256);
                                   // step 2
          // first make EE certs
      char *fmt = "MR", *fp, e[2];
      e[1] = 0;
      char eename[20];
      strcpy(eename, subjname);
      
      for (fp = fmt; *fp; fp++)
        {
        e[0] = *fp;
        char *f = &eename[12];
        if (!dots) f = &eename[1];
        else if (dots <= 2) f = &eename[(dots == 1)? 2: 8];
        strcpy(f, e);
        strcat(strcpy(subjfile, eename), ".cer");
        fill_cert(eename, &cert, &issuer, snum, *fp, dots, 0);
        setSignature(&cert.toBeSigned.self, &cert.signature, issuerkeyfile, 0);
        struct ROA *roap;
          // put cert into roa/manifest
        if (*fp == 'M') roap = &manifest;
        else roap = &roa;
        if (!inject_casn(&roap->content.signedData.certificates.self, 0)) 
            fatal(4, "signedData");
        struct Certificate *certp = (struct Certificate *)member_casn(
          &roap->content.signedData.  certificates.self, 0);
        copy_casn(&certp->self, &cert.self);
        }
                                     // step 3 make CRL
      struct CertificateRevocationList crl;
      CertificateRevocationList(&crl, (ushort)0);
      struct CertificateRevocationListToBeSigned *crltbsp =
        &crl.toBeSigned;
      fill_cert(subjname, &cert, &issuer, 0, (char)0, dots, 0);
      write_casn_num(&crltbsp->version.self, 1);
      copy_casn(&crltbsp->signature.self, &cert.toBeSigned.signature.self);
      copy_casn(&crltbsp->issuer.self, &cert.toBeSigned.subject.self);
      copy_casn(&crl.algorithm.self, &cert.algorithm.self);
      copy_casn(&crl.toBeSigned.issuer.self, &cert.toBeSigned.issuer.self);
      write_casn_time(&crltbsp->lastUpdate.utcTime, now);
      write_casn_time(&crltbsp->nextUpdate.utcTime, now + (30 * 24 * 3600));
//      struct CRLEntry *crlEntryp = (struct CRLEntry *)inject_casn(
//        &crltbsp->revokedCertificates.self, 0);
//      write_casn_num(&crlEntryp->userCertificate, 1);
//      write_casn_time(&crlEntryp->revocationDate.utcTime, now); 
      struct CRLExtension *crlextp = (struct CRLExtension *)inject_casn(
        &crltbsp->extensions.self, 0);
      write_objid(&crlextp->extnID, id_cRLNumber);
      write_casn_num(&crlextp->extnValue.cRLNumber, (long)1);
      
      struct Extension *iextp;
      if (!(iextp = findExtension(&ctftbsp->extensions,
        id_authKeyId))) fatal(4, "AuthorityKeyIdentifier");
      crlextp = (struct CRLExtension *)inject_casn(&crltbsp->extensions.self, 1);
      copy_casn(&crlextp->self, &iextp->self);
      if (!(iextp = findExtension(&ctftbsp->extensions,
        id_cRLDistributionPoints))) fatal(4, "CRLIssuingDistributionPoint");
      crlextp = (struct CRLExtension *)inject_casn(&crltbsp->extensions.self, 2);
      write_objid(&crlextp->extnID, id_issuingDistributionPoint);
      struct DistributionPoint *dbp;
      if (!(dbp = (struct DistributionPoint *)member_casn(
        &iextp->extnValue.cRLDistributionPoints.self, 0)))
        fatal(4,"CRLIssuingDistributionPoints");
      uchar *tbc;
      int tblth = size_casn(&dbp->self);
      tbc = (uchar *)calloc(1, tblth);
      encode_casn(&dbp->self, tbc);
      decode_casn(&crlextp->extnValue.issuingDistributionPoint.self, tbc);
  
      setSignature(&crl.toBeSigned.self, &crl.signature, issuerkeyfile, 0);
      char *crlfile = (char *)calloc(1, strlen(subjfile) + 6);
      strcpy(crlfile, subjname);
      crlfile[0] = 'L';
      char *cp;
      if (!dots) cp = &crlfile[1];
      else if (dots > 2) cp = &crlfile[12];
      else cp = &crlfile[(dots == 1)? 2: 8];
      strcpy(cp, ".crl");
      put_casn_file(&crl.self, crlfile, 0);
      if (!dots) printf(">f+++++++ %s\n", crlfile);
      else printf(">f+++++++ %s/%s\n", dirname, crlfile);
      add_to_manifest(&manp->fileList, crlfile, &crl.self);
      long siz = dump_size(&crl.self);
      char *rawp = (char *)calloc(1, siz + 4);
      siz = dump_casn(&crl.self, rawp);
      strcpy(strchr(crlfile, 'c'), "raw");
      int fd = open(crlfile, (O_WRONLY | O_CREAT | O_TRUNC), (S_IRWXU));
      if (fd < 0) fatal(6, crlfile);
      if (write(fd, rawp, siz) < 0) perror(crlfile);
      close(fd);
      free(crlfile);
      free(rawp);
      }
    else if (get_casn_file(&manifest.self, manifestfile, 0) < 0)
      fatal(1, manifestfile);
    snum = 1;
    if (dots == 0) snum = rir;
    else if (dots == 1) snum = nir;
    else snum = isp;
    if (!dots) sprintf(subjname, "C%d", rir);
    else if (dots == 1) sprintf(subjname, "C%d.%05d", rir, nir);
    else if (dots >= 2) sprintf(subjname, "C%d.%05d.%03d", rir, nir, isp);
    else fatal(9, argv[curr_step + 1]);
    int numcert;
    if (dots <= 2) 
      {
      for (numcert = 0; numcert < numcerts; numcert++, snum++)
        {
        if (numcerts > 1)  // don't need to do this for first
          {              // and besides it would clobber appended R or M
          if (dots == 0) subjname[1] = snum + '0';
          else if (dots == 1) sprintf(&subjname[3], "%05ld", snum);
          else if (dots == 2) sprintf(&subjname[9], "%03ld", snum);
          }
        strcat(strcpy(subjfile, subjname), ".cer");
        fill_cert(subjname, &cert, &issuer, snum, (char)0, dots, numaddrs);
        setSignature(&cert.toBeSigned.self, &cert.signature, issuerkeyfile, 0);
        add_to_manifest(&manp->fileList, subjfile, &cert.self);
        if (!dots) printf(">f+++++++ %s\n", subjfile);
        else printf(">f+++++++ %s/%s\n", dirname, subjfile);
        write_cert_and_raw(subjfile, &cert);
        }
      }
      // step 5 make roa
    char *msg;
    if (first_time)
      {
      // insert the AS number
      sgdp = &roa.content.signedData;
      struct Extension *extp;
      for (extp = (struct Extension *)member_casn(&issuer.toBeSigned.extensions.
        self, 0); extp && diff_objid(&extp->extnID, id_pe_autonomousSysNum) != 0;
  	extp = (struct Extension *)next_of(&extp->self));
      if (extp == NULL) fatal(4, "ASnumber");
      struct RouteOriginAttestation *roap = &sgdp->encapContentInfo.eContent.roa;
      long asnum;
      struct ASNumberOrRangeA *asnorrp = (struct ASNumberOrRangeA *)
        member_casn(&extp->extnValue.autonomousSysNum.asnum.asNumbersOrRanges.
          self, 0);
      if (tag_casn(&asnorrp->self) == ASN_SEQUENCE) 
        read_casn_num(&asnorrp->range.min, &asnum);
      else read_casn_num(&asnorrp->num, &asnum);
      write_casn_num(&roap->asID, asnum);
      for (extp = (struct Extension *)member_casn(&issuer.toBeSigned.extensions.
        self, 0); extp && diff_objid(&extp->extnID, id_pe_ipAddrBlock) != 0;
  	extp = (struct Extension *)next_of(&extp->self));
      if (extp == NULL) fatal(4, "IPAdressBlock");
  
      // look up the ipAddrBlock extension and copy over
      getIPAddresses(&roap->ipAddrBlocks, &extp->extnValue.ipAddressBlock,
        0, 0, -1, -1);
  
      // sign the message
      if ((msg = signCMS(&roa, issuerkeyfile, 0))) fatal(5, msg);
      add_to_manifest(&manp->fileList, roafile, &roa.self);
      if (!dots) printf(">f+++++++ %s\n", roafile);
      else printf(">f+++++++ %s/%s\n", dirname, roafile);
      write_roa_and_raw(roafile, &roa);
      }
        // step 6 make manifest
    if ((msg = signCMS(&manifest, issuerkeyfile, 0))) fatal(5, msg);
    if (!dots) printf(">f+++++++ %s\n", manifestfile);
    else printf(">f+++++++ %s/%s\n", dirname, manifestfile);
    write_roa_and_raw(manifestfile, &manifest);
    }
  if (dots < 3)
    {
    now = time((time_t *)0);
    write_casn_time(&casn, now);
    read_casn(&casn, tbuf);
    fprintf(stderr, "End  %s\n", (char *)tbuf);
    }
  fatal(0, manifestfile);
  return 0;
  }

