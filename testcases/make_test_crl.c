/* $Id: make_crl.c 453 2008-05-28 15:30:40Z cgardiner $ */

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
#include <time.h>
#include "crlv2.h"
#include "certificate.h"
#include "extensions.h"
#include <cryptlib.h>
#include <roa.h>

extern int adjustTime(struct casn *, long, char *);

char *msgs[] =
  {
  "Finished %s OK\n",
  "Usage: CRLfile startdelta enddelta\n",
  "Can't get %s\n",       // 2
  "Invalid CRL number %s\n",
  "Error signing CRL\n",   // 4
  "Error %s\n",
  "Error writing CRL to %s\n",  // 6
  "Invalid time delta %s\n",
  };

static int fatal(int err, char *param)
  {
  fprintf(stderr, msgs[err], param);
  exit(err);
  }

static struct Extension *findExtension(struct Extensions *extsp, char *id)
  {
  struct Extension *extp;
  if (!num_items(&extsp->self)) return (struct Extension *)0; 
  for (extp = (struct Extension *)member_casn(&extsp->self, 0); extp;
    extp = (struct Extension *)next_of(&extp->self))
    {
    if (!diff_objid(&extp->extnID, id)) break;
    }
  return extp;
  }

static long getCertNum(char *certfile)
  {
  char *c;
  for (c = certfile; *c && *c != '.'; c++);
  if (!*c) strcpy(c, ".cer");
  struct Certificate cert;
  Certificate(&cert, (ushort)0);
  if (get_casn_file(&cert.self, certfile, 0) < 0) fatal(2, certfile);
  long num;
  read_casn_num(&cert.toBeSigned.serialNumber, &num);
  delete_casn(&cert.self);
  return num;
  }

static void make_fullpath(char *fullpath, char *locpath)
  {
  // CRL goes in issuer's directory, e.g.
  // L1.crl goes nowhere else, 
  // L11.crl goes into C1/, 
  // L121.crl goes into C1/2 
  // L1231.crl goes into C1/2/3
  char *f = fullpath, *l = locpath;
  if (strlen(locpath) > 6) 
    {
    *f++ = 'C';
    *l++; 
    *f++ = *l++;  // 1st digit
    *f++ = '/';
    if (l[1] != '.')  // 2nd digit
      {
      *f++ = *l++;  
      *f++ = '/';
      if (l[1] != '.') // 3rd digit
        {
        *f++ = *l++;
        *f++ = '/';
        }
      }
    }
  strcpy(f, locpath);
  }

static void signCRL(struct CertificateRevocationList *crlp, char *certname)
  {
  char *c, keyfile[80];
  strcpy(keyfile, certname);
  for (c = keyfile; *c && *c != '.'; c++);
  strcpy(c, ".p15");

  CRYPT_CONTEXT hashContext;
  CRYPT_CONTEXT sigKeyContext;
  CRYPT_KEYSET cryptKeyset;
  uchar hash[40];
  uchar *signature = NULL;
  int ansr = 0, signatureLength;
  char *msg;
  uchar *signstring = NULL;
  int sign_lth;

  sign_lth = size_casn(&crlp->toBeSigned.self);
  signstring = (uchar *)calloc(1, sign_lth);
  sign_lth = encode_casn(&crlp->toBeSigned.self, signstring);
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
    if ((ansr = cryptCreateSignature(signature, signatureLength+20, 
      &signatureLength, sigKeyContext, hashContext)) != 0) msg = "signing";
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
    else if ((ansr = write_casn_bits(&crlp->signature, signstring, ansr, 0)) < 0)
      msg = "writing signature";
    else ansr = 0;
    }
  if (signstring != NULL) free(signstring);
  if (signature != NULL ) free(signature);
  if (ansr) fatal(5, msg);
  }

int main(int argc, char **argv)
  {
  if (argc < 4) fatal(1, (char *)0);
  struct stat tstat;
  fstat(0, &tstat);
  int filein = (tstat.st_mode & S_IFREG);
  char certname[40], crlname[40];
  memset(certname, 0, 40);
  memset(crlname, 0, 40);
  char *c;
  strcpy(crlname, argv[1]);
  for (c = crlname; *c && *c != '.'; c++);
  int crlnum;
  if (sscanf(&c[-1], "%d", &crlnum) != 1) fatal(3, &c[-1]);
  if (!*c) strcpy(c, ".crl");
  strcpy(certname, argv[1]);
  certname[0] = 'C';
  for (c = certname; *c && *c != '.'; c++);
  strcpy(--c, ".cer");
  
  struct CertificateRevocationList crl;
  struct Certificate cert;

  CertificateRevocationList(&crl, (ushort)0);
  Certificate(&cert, (ushort)0);
  if (get_casn_file(&cert.self, certname, 0) < 0) fatal(2, certname);
  struct CertificateRevocationListToBeSigned *crltbsp = 
    &crl.toBeSigned;
  struct CertificateToBeSigned *ctbsp = &cert.toBeSigned;
  write_casn_num(&crltbsp->version.self, 2);
  copy_casn(&crltbsp->signature.self, &ctbsp->signature.self);
  copy_casn(&crl.algorithm.self, &ctbsp->signature.self);
  copy_casn(&crltbsp->issuer.self, &ctbsp->subject.self);

  time_t now = time((time_t)0);
  clear_casn(&crltbsp->lastUpdate.self);
  clear_casn(&crltbsp->nextUpdate.self);
  if (adjustTime(&crltbsp->lastUpdate.utcTime, now, argv[2]))
    fatal(7, argv[2]);
  if (adjustTime(&crltbsp->nextUpdate.utcTime, now, argv[3]))
    fatal(7, argv[3]);

  struct Extension *iextp;
  struct CRLExtension *extp;
  int numext = 0;
  extp = (struct CRLExtension *)inject_casn(&crltbsp->extensions.self, numext++);
  write_objid(&extp->extnID, id_cRLNumber);
  write_casn_num(&extp->extnValue.cRLNumber, crlnum);
  extp = (struct CRLExtension *)inject_casn(&crltbsp->extensions.self, numext++);
  iextp = findExtension(&ctbsp->extensions, id_subjectKeyIdentifier);
  write_objid(&extp->extnID, id_authKeyId);
  copy_casn(&extp->extnValue.authKeyId.keyIdentifier, 
    &iextp->extnValue.subjectKeyIdentifier);
  extp = (struct CRLExtension *)inject_casn(&crltbsp->extensions.self, numext++);
  write_objid(&extp->extnID, id_issuingDistributionPoint);
  iextp = findExtension(&ctbsp->extensions, id_cRLDistributionPoints);
  struct DistributionPoint *dp = (struct DistributionPoint *)member_casn(
    &iextp->extnValue.cRLDistributionPoints.self, 0);
  copy_casn(&extp->extnValue.issuingDistributionPoint.distributionPoint.self,
    &dp->distributionPoint.self);
           // now get the revocation info
  int numcerts;
  char certbuf[40];
  struct CRLEntry *crlentryp;
  if (!filein)
    {
    fprintf(stdout, "List certificates.  Format is:\n");
    fprintf(stdout, "Certfile mm/dd/yy\n");
    }
  for (numcerts = 0; fgets(certbuf, 40, stdin) && certbuf[0] > ' '; )
    {
    long certnum;
    char subjfile[80], delta[20];
    sscanf(certbuf, "%s %s\n", subjfile, delta);

    certnum = getCertNum(subjfile);
    crlentryp = (struct CRLEntry *)inject_casn(&crltbsp->revokedCertificates.self,
      numcerts++);
    write_casn_num(&crlentryp->userCertificate, (long)certnum);
    read_casn_time(&crltbsp->lastUpdate.utcTime, (ulong *)&now);
    adjustTime(&crlentryp->revocationDate.utcTime, now, delta);
    }
  signCRL(&crl, certname);
  char fullpath[40];
  make_fullpath(fullpath, crlname);
  if (put_casn_file(&crl.self, crlname, 0) < 0) fatal(6, crlname); 
  if (put_casn_file(&crl.self, fullpath, 0) < 0) fatal(2, fullpath);
  int siz = dump_size(&crl.self);
  char *rawp = (char *)calloc(1, siz + 4);
  siz = dump_casn(&crl.self, rawp);
  for (c = crlname; *c && *c != '.'; c++);
  strcpy(c, ".raw");
  int fd = open(crlname, (O_WRONLY | O_CREAT | O_TRUNC), (S_IRWXU));
  if (fd < 0) fatal(6, crlname);
  if (write(fd, rawp, siz) < 0) perror(crlname);
  close(fd);
  free(rawp);
  fatal(0, crlname);
  return 0;
  }  
