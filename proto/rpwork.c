/*
  $Id: rpwork.h 888 2009-11-17 17:59:35Z gardiner $
*/

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
 * Copyright (C) Raytheon BBN Technologies Corp. 2009-2010.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK ***** */
#include "rpwork.h"
#include <time.h>
#include <fcntl.h>
#include "logutils.h"

extern struct done_certs done_certs;

static char Xvalidity_dates[40];
static scm *locscmp;
static scmcon *locconp;
struct Certificate myrootcert;
char myrootfullname[PATH_MAX];
struct ipranges certranges, ruleranges, lessranges, fromranges;
char errbuf[160]; 
char currskibuf[SKIBUFSIZ], nextskibuf[SKIBUFSIZ], skibuf[SKIBUFSIZ];

char *Xcrldp;
char *Xcp;
char *Xrpdir;
unsigned int XrpdirId;

int locflags;

extern struct keyring keyring;

static void free_keyring()
  {
  if (keyring.filename) free(keyring.filename);
  if (keyring.label) free(keyring.label);
  if (keyring.password) free(keyring.password);
  keyring.filename = keyring.label = keyring.password = (char *)0;
  }

#ifdef DUMP_THEM

static struct casn *get_subject_name(struct Name *subjp)
  {
  struct RelativeDistinguishedName *rdnp = (struct RelativeDistinguishedName *)
      member_casn(&subjp->rDNSequence.self, 0);
  struct AttributeValueAssertion *avap = (struct AttributeValueAssertion *)
      member_casn(&rdnp->self, 0);
  struct casn *casnp = (struct casn *)&avap->value.commonName;
  return casnp;
  }

static void dump_test_cert(struct done_cert *done_certp, int orig)
  {
  char locbuf[20], namebuf[20];
  int fd, size;
  char *buf;
  struct Certificate *certp;
  struct casn *casnp;
  if (orig)
    {
    certp = done_certp->origcertp;
    size = dump_size(&certp->self);
    buf = (char *)calloc(1, size + 2);
    size = dump_casn(&certp->self, buf);
    casnp = get_subject_name(&certp->toBeSigned.subject);
    fd = read_casn(casnp, (uchar *)namebuf);
    namebuf[fd] = 0;
    sprintf(locbuf, "o%s.raw", namebuf);
    fd = open(locbuf, (O_CREAT | O_WRONLY | O_TRUNC), 0777);
    write(fd, buf, size);
    close(fd);
    }
  size = dump_size(&done_certp->paracertp->self);
  buf = (char *)calloc(1, size + 2);
  size = dump_casn(&done_certp->paracertp->self, buf);
  casnp = get_subject_name(&done_certp->paracertp->toBeSigned.subject);
  fd = read_casn(casnp, (uchar *)namebuf);
  namebuf[fd] = 0;
  sprintf(locbuf, "p%s.raw", namebuf);
  fd = open(locbuf, (O_CREAT | O_WRONLY | O_TRUNC), 0777);
  write(fd, buf, size);
  close(fd);
  }

static void dump_test_certs(int orig)
  {
  int num;
  for (num = 0; num < done_certs.numcerts; num++)
    {
    dump_test_cert(&done_certs.done_certp[num], orig);
    }
  }

#endif

static int add_done_cert(struct done_cert *tmp_done_certp)
  {
  if (!done_certs.numcerts)
    {
    done_certs.done_certp = (struct done_cert *)
      calloc(1, sizeof(struct done_cert));
    done_certs.numcerts = 1;
    }
  else done_certs.done_certp = (struct done_cert *)
      realloc(done_certs.done_certp,
      (sizeof(struct done_cert) * (++done_certs.numcerts)));
  struct done_cert *done_certp =
    &done_certs.done_certp[done_certs.numcerts - 1];
  strcpy(done_certp->ski, tmp_done_certp->ski);
  done_certp->origID = tmp_done_certp->origID;
  done_certp->origflags = tmp_done_certp->origflags;
  done_certp->origcertp = tmp_done_certp->origcertp;
  done_certp->paracertp = tmp_done_certp->paracertp;
  strcpy(done_certp->filename, tmp_done_certp->filename);
  done_certp->perf = tmp_done_certp->perf;
  return done_certs.numcerts - 1;
  }

static int format_aKI(char *namep, struct casn *idp)
  {
  int lth = vsize_casn(idp);
  uchar *uc, casnbuf[64];
  read_casn(idp, casnbuf);
  char *c;
  for (uc = casnbuf, c = namep; uc < &casnbuf[lth]; c += 3)
    {
    int i;
    i = *uc++;
    sprintf(c, "%02X:", i);
    }
  *(--c) = 0;
  return (c - namep);
  }

static int add_paracert2DB(struct done_cert *done_certp)
  {
  int ansr;
  char fullname[PATH_MAX], ski[80];
  ulong flags;
  struct cert_answers *cert_answersp;
  struct cert_ansr *cert_ansrp;
  uint dbid;
  ansr = findorcreatedir(locscmp, locconp, Xrpdir, &dbid);
  sprintf(fullname, "%s/%s", Xrpdir, done_certp->filename);
  ansr = delete_object(locscmp, locconp, done_certp->filename, Xrpdir,
    fullname, dbid);
  if ((ansr = put_casn_file(&done_certp->paracertp->self, fullname, 0)) < 0)
    return ansr;
  ansr = add_cert(locscmp, locconp, done_certp->filename, fullname, XrpdirId, 
     0, OT_CER, &dbid, 1); 
  if (ansr >= 0)
    {
    flags = done_certp->origflags & ~(SCM_FLAG_NOCHAIN);
    struct Extension *extp = find_extn(done_certp->paracertp,
      id_subjectKeyIdentifier, 0);
    format_aKI(ski, &extp->extnValue.subjectKeyIdentifier);
    cert_answersp = find_cert_by_aKI(ski, (char *)0, locscmp, locconp);
    if (!cert_answersp || cert_answersp->num_ansrs < 0) return -1;
    int i = 0;
    for (cert_ansrp = &cert_answersp->cert_ansrp[0];
      i < cert_answersp->num_ansrs; i++, cert_ansrp++)
      {      // if it's not a paracert, skip it
      if (!strcmp(cert_ansrp->dirname, Xrpdir)) break;
      }
    if (i >= cert_answersp->num_ansrs) ansr = -1;
    }
  if (ansr >= 0)
    {
    flags |= SCM_FLAG_ISPARACERT;
    flags &= ~(SCM_FLAG_HASPARACERT | SCM_FLAG_ISTARGET);
    if ((ansr = set_cert_flag(locconp, cert_ansrp->local_id, flags)) ||
      (ansr = set_cert_flag(locconp, done_certp->origID,
      done_certp->origflags)))
      return ansr;
    log_msg(LOG_INFO, "Added %s to DB", fullname);
    return 1;
    }
  else
    log_msg(LOG_ERR, "Adding %s to DB failed with error %d",
	    fullname, -ansr);
  return ansr;
  }

static struct done_cert *have_already(char *ski)
  {
  int i;
  for (i = 0;
    i < done_certs.numcerts && strcmp(done_certs.done_certp[i].ski, ski);
     i++);
  if (i < done_certs.numcerts) return &done_certs.done_certp[i];
  return (struct done_cert *)0;
  }

static struct AddressesOrRangesInIPAddressChoiceA *find_IP(int typ,
    struct Extension *extp)
  {
  uchar fambuf[4];
  int loctyp;
  if (typ == IPv4) loctyp = 1;
  else if (typ == IPv6) loctyp = 2;
  else return (struct AddressesOrRangesInIPAddressChoiceA *)0;
  struct IpAddrBlock *ipAddrBlock = &extp->extnValue.ipAddressBlock;
  struct IPAddressFamilyA *ipFamp;
  for (ipFamp = (struct IPAddressFamilyA *)member_casn(
        &ipAddrBlock->self, 0);  ipFamp;
    ipFamp = (struct IPAddressFamilyA *)next_of(&ipFamp->self))
    {
    read_casn(&ipFamp->addressFamily, fambuf);
    if (fambuf[1] == loctyp)  // OK the cert has some
     return &ipFamp->ipAddressChoice.addressesOrRanges;
    }
  return (struct AddressesOrRangesInIPAddressChoiceA *)0;
  }

static void mk_certranges(struct ipranges *rangep,
  struct Certificate *certp)
  {
  if (rangep->numranges > 0 || rangep->iprangep)
      clear_ipranges(rangep);
  struct Extension *extp = find_extn(certp, id_pe_ipAddrBlock, 0);
  int num;
  struct IPAddressOrRangeA *ipAddrOrRangep;
  struct iprange *certrangep;
  struct AddressesOrRangesInIPAddressChoiceA *ipAddrOrRangesp;
  if ((ipAddrOrRangesp = find_IP(IPv4, extp)))
    {
    for (num = 0, ipAddrOrRangep = (struct IPAddressOrRangeA *)
      member_casn(&ipAddrOrRangesp->self, 0);
      ipAddrOrRangep; ipAddrOrRangep = (struct IPAddressOrRangeA *)
      next_of(&ipAddrOrRangep->self))
      {
      certrangep = inject_range(rangep, num++);
      certrangep->typ = IPv4;
      cvt_asn(certrangep, ipAddrOrRangep);
      }
    }
  if ((ipAddrOrRangesp = find_IP(IPv6, extp)))
    {
    for (ipAddrOrRangep = (struct IPAddressOrRangeA *)
      member_casn(&ipAddrOrRangesp->self, 0);
      ipAddrOrRangep; ipAddrOrRangep = (struct IPAddressOrRangeA *)
      next_of(&ipAddrOrRangep->self))
      {
      certrangep = inject_range(rangep, num++);
      certrangep->typ = IPv6;
      cvt_asn(certrangep, ipAddrOrRangep);
      }
    }
  extp = find_extn(certp, id_pe_autonomousSysNum, 0);
  struct AsNumbersOrRangesInASIdentifierChoiceA *asNumbersOrRangesp =
    &extp->extnValue.autonomousSysNum.asnum.asNumbersOrRanges;
  struct ASNumberOrRangeA *asNumOrRangep;
  for (asNumOrRangep = (struct ASNumberOrRangeA *)
    member_casn(&asNumbersOrRangesp->self, 0); asNumOrRangep;
    asNumOrRangep = (struct ASNumberOrRangeA *)next_of(&asNumOrRangep->self))
    {
    certrangep = inject_range(rangep, num++);
    certrangep->typ = ASNUM;
    cvt_asnum(certrangep, asNumOrRangep);
    }
  certrangep = inject_range(rangep, num++);
  certrangep->typ = 0;
  }

static int snum_sfx;

static struct Certificate *mk_paracert(struct Certificate *origcertp, 
  int flags)
  {
  struct Certificate *paracertp = (struct Certificate *)calloc(1,
    sizeof(struct Certificate));
  Certificate(paracertp, (ushort)0);
  copy_casn(&paracertp->self, &origcertp->self);
  copy_casn(&paracertp->toBeSigned.issuer.self,
    &myrootcert.toBeSigned.subject.self);
  uchar locbuf[32];
  memset(locbuf, 0, sizeof(locbuf));
  time_t now = time((time_t *)0);
  uchar *uc;
  for (uc = &locbuf[3]; uc >= locbuf; *uc-- = (now & 0xFF), now >>= 8);
  now = ++snum_sfx;
  for (uc = &locbuf[5]; uc > &locbuf[3]; *uc-- = (now & 0xFF), now >>= 8);
  write_casn(&paracertp->toBeSigned.serialNumber, locbuf, 6);
  if (*Xvalidity_dates)
    {
    if (*Xvalidity_dates == 'C') {}  // do nothing
    else if (*Xvalidity_dates == 'R')
      copy_casn(&paracertp->toBeSigned.validity.self,
        &myrootcert.toBeSigned.validity.self);
    else
      {
      struct Validity *validityp = &paracertp->toBeSigned.validity;
      clear_casn(&validityp->self);
      struct casn *casnp = (Xvaliddates.lodate.type == ASN_UTCTIME)?
        &validityp->notBefore.utcTime:
        &validityp->notBefore.generalTime;
      copy_casn(casnp, &Xvaliddates.lodate);
      casnp = (Xvaliddates.hidate.type == ASN_UTCTIME)?
        &validityp->notAfter.utcTime:
        &validityp->notAfter.generalTime;
      copy_casn(casnp, &Xvaliddates.hidate);
      }
    }
  struct Extension *fextp, *textp;
  if (!Xcrldp || (*Xcrldp == 'C' && !Xcrldp[1])) { }  // do nothing 
  else if ((*Xcrldp == 'R' && !Xcrldp[1]))
    {
    fextp = find_extn(&myrootcert, id_cRLDistributionPoints, 0);
    textp = find_extn(paracertp, id_cRLDistributionPoints, 1);
    copy_casn(&textp->self, &fextp->self);
    }
  else if (*Xcrldp != 'C' || Xcrldp[1]) 
    {
    textp = find_extn(paracertp, id_cRLDistributionPoints, 1);
    clear_casn(&textp->extnValue.cRLDistributionPoints.self);
    write_objid(&textp->extnID, id_cRLDistributionPoints);
    char *pt, *ept;
    int numpts = 0;
    for (pt = Xcrldp; pt && *pt; pt = nextword(pt))
      {
      struct DistributionPoint *distp = (struct DistributionPoint *)
        inject_casn(&textp->extnValue.cRLDistributionPoints.self, numpts++);
      if (!distp)
        {
        sprintf(errbuf, "Too many CRLDP extensions");
        return (struct Certificate *)0;
        }
      struct GeneralName *gennamep = (struct GeneralName *) inject_casn(
        &distp->distributionPoint.fullName.self, 0);
      if (!gennamep)
        {
        sprintf(errbuf, "Too many general names in CRLDP extensions");
        return (struct Certificate *)0;
        }
      for (ept = pt; *ept > ' '; ept++);
      write_casn(&gennamep->url, (uchar *)pt, ept - pt);
      }
    }
  if (Xcp && *Xcp != 'C')
    {
    textp = find_extn(paracertp, id_certificatePolicies, 1);
    if (*Xcp == 'R')
      {
      fextp = find_extn(&myrootcert, id_certificatePolicies, 0);
      copy_casn(&textp->self, &fextp->self);
      }
    else  // D or specified one
      {
      clear_casn(&textp->extnValue.self);
      write_objid(&textp->extnID, id_certificatePolicies);
      struct PolicyInformation *polInfop = (struct PolicyInformation *)
        inject_casn(&textp->extnValue.certificatePolicies.self, 0);
      if (*Xcp == 'D') write_objid(&polInfop->policyIdentifier,
        id_pkix_rescerts_policy);
      else write_objid(&polInfop->policyIdentifier, Xcp);
      }
    }
  if (Xaia && *Xaia != 'C' && Xaia[0] != 0 && Xaia[1] > 0)
    {
    textp = find_extn(paracertp, id_pkix_authorityInfoAccess, 1);
    clear_casn(&textp->extnValue.self);
    write_objid(&textp->extnID, id_pkix_authorityInfoAccess);
    struct AccessDescription *adp = (struct AccessDescription *)inject_casn(
      &textp->extnValue.authorityInfoAccess.self, 0);
    write_objid(&adp->accessMethod, id_ad_caIssuers);
    write_casn(&adp->accessLocation.url, (uchar *)Xaia, strlen(Xaia));
    }
  struct Extension *skiExtp, // root's ski
        *akiExtp;   // new cert's aki
  if (!(skiExtp = find_extn(&myrootcert, id_subjectKeyIdentifier, 0)))
    {
    sprintf(errbuf, "Certificate has no SKI.");
    return (struct Certificate *)0;
    }
  if (!(akiExtp = find_extn(paracertp, id_authKeyId, 0)))
    {
    if ((flags & SCM_FLAG_TRUSTED)) 
      {    
      akiExtp = (struct Extension *)inject_casn(
        &paracertp->toBeSigned.extensions.self, 0);
      write_objid(&akiExtp->extnID, id_authKeyId);
      }
    else 
      {
      sprintf(errbuf, "Certificate has no AKI.");
      return (struct Certificate *)0;
      }
    }
  copy_casn(&akiExtp->extnValue.authKeyId.keyIdentifier,
      &skiExtp->extnValue.subjectKeyIdentifier);
  mk_certranges(&certranges, paracertp);
  return paracertp;
  }

static void fill_done_cert(struct done_cert *done_certp, char *cSKI,
    char *filename, struct Certificate *certp, ulong local_id, int flags)
  {
  strcpy(done_certp->ski, cSKI);
  memset(done_certp->filename, 0, sizeof(done_certp->filename));
  strcpy(done_certp->filename, filename);
  done_certp->origcertp = (struct Certificate *)
    calloc(1, sizeof(struct Certificate));
  Certificate(done_certp->origcertp, (ushort)0);
  copy_casn(&done_certp->origcertp->self, &certp->self);
  done_certp->origID = local_id;
  done_certp->origflags = flags;
  done_certp->paracertp =  mk_paracert(certp, flags);
  done_certp->perf = 0;
  }

int get_CAcert(char *ski, struct done_cert **done_certpp)
  {  // use INTERSECTION_ALWAYS
  struct Certificate *certp = (struct Certificate *)0;
  int i, j;
  struct done_cert *done_certp;

  if (ski && (done_certp = have_already(ski)))
    {
    *done_certpp = done_certp;
    i = 0;
    }
  else   //  no, get it from DB as certp
    {
    int ansr;
    struct cert_answers *cert_answersp =
      find_cert_by_aKI(ski, (char *)0, locscmp, locconp);
    if (!cert_answersp && cert_answersp->num_ansrs < 0) return -1;
    struct cert_ansr *cert_ansrp, *this_cert_ansrp;
    ansr = cert_answersp->num_ansrs;
    if (ansr < 0) return ansr;
    i = j = 0;
    int have_para = 0;
    for (cert_ansrp = &cert_answersp->cert_ansrp[0];
      i < cert_answersp->num_ansrs; i++, cert_ansrp++)
      {      // if it's a paracert, note that and skip it
      if (!strcmp(cert_ansrp->dirname, Xrpdir))
        {
        have_para++;
        continue;
        }
      certp = (struct Certificate *)calloc(1, sizeof(struct Certificate));
      Certificate(certp, (ushort)0);
      if ((ansr = get_casn_file(&certp->self, cert_ansrp->fullname, 0)) < 0)
        return ERR_SCM_COFILE;
      this_cert_ansrp = cert_ansrp;
      j++;
      }
    if (!j) 
      {
      sprintf(errbuf, "No CA certificate found for SKI %s\n", ski);
      return -1;
      }
    else if (j > 2 || (j == 2 && !have_para)) 
      {
      sprintf(errbuf, "Found %d certificates for SKI %s\n", j, ski);
      return -1;
      }
    get_casn_file(&certp->self, this_cert_ansrp->fullname, 0);
    struct Certificate *paracertp = mk_paracert(certp, this_cert_ansrp->flags);
    if (!paracertp) ansr = ERR_SCM_BADSKIFILE;
    else
      {
      struct done_cert done_cert;
      fill_done_cert(&done_cert, ski, this_cert_ansrp->filename, certp,
        this_cert_ansrp->local_id, this_cert_ansrp->flags);
      if ((ansr = add_done_cert(&done_cert)) >= 0)
        {
        done_certp = &done_certs.done_certp[ansr];
        *done_certpp = done_certp;
        }
      }
/*
    free(cert_answersp->cert_ansrp);
    cert_answersp->num_ansrs = 0;
    cert_answersp->cert_ansrp = NULL;
*/
    if (ansr < 0) return ansr;
    i = 1;
    }
  return i;
  }

static int CryptInitState = 0;

static int sign_cert(struct Certificate *certp)
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

  if ((sign_lth = size_casn(&certp->toBeSigned.self)) < 0)
      return ERR_SCM_SIGNINGERR;
  signstring = (uchar *)calloc(1, sign_lth);
  sign_lth = encode_casn(&certp->toBeSigned.self, signstring);
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
    if ((ansr = cryptCreateSignature(signature, signatureLength + 20, 
      &signatureLength, sigKeyContext, hashContext)) != 0) msg = "signing";
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
        if ((ansr = write_casn_bits(&certp->signature, signstring, ansr, 0)) < 0)
        msg = "writing signature";
      else ansr = 0;
      }
    }
  if (signstring != NULL) free(signstring);
  if (signature != NULL ) free(signature);
  if (ansr)
    {
    ansr = ERR_SCM_SIGNINGERR;
    sprintf(errbuf, "Error %s\n", msg);
    fflush(stderr);
    }
  return ansr;
  }

static void save_cert_answers(struct cert_answers *to_cert_answersp,
  struct cert_answers *from_cert_answersp)
  {
  int numkid, numkids = from_cert_answersp->num_ansrs;
  to_cert_answersp->num_ansrs = numkids;
  to_cert_answersp->cert_ansrp = (struct cert_ansr *)
    calloc(numkids, sizeof(struct cert_ansr));
  for (numkid = 0; numkid < numkids; numkid++)
    {
    to_cert_answersp->cert_ansrp[numkid] =
      from_cert_answersp->cert_ansrp[numkid];
    }
  }


static void make_ASnum(struct ASNumberOrRangeA *asNumberOrRangep,
  struct iprange *iprangep)
  {
  int asnum;
  uchar *u, *e;

  for (asnum = 0, u = iprangep->lolim, e = &u[4]; u < e; u++)
    {
    asnum <<= 8;
    asnum += *u;
    }
  if (memcmp(iprangep->lolim, iprangep->hilim, 4) == 0)
    write_casn_num(&asNumberOrRangep->num, asnum);
  else
    {
    write_casn_num(&asNumberOrRangep->range.min, asnum);
    for (asnum = 0, u = iprangep->hilim, e = &u[4]; u < e; u++)
      {
      asnum <<= 8;
      asnum += *u;
      }
    write_casn_num(&asNumberOrRangep->range.max, asnum);
    }
  }

static void make_IPAddrOrRange(struct IPAddressOrRangeA *ipAddrOrRangep,
  struct iprange *tiprangep)
  {
/*
Procedure:
1. Running from left to right, find where the low and high of tiprangep differ
   Count the number of bits where they match
2. IF beyond that point lolim is all zeroes and hilim all ones, write a prefix
3. ELSE make a range thus
    Find the last non-zero byte in the minimum
    Write those bytes to the min field
    Fill in the number of unused bits in the min field
    Find the last non-FF byte in the max field
    Write those bytes in the max field
    Fill in the number of unused bits in the max field
*/
  int lth = tiprangep->typ == IPv4? 4: 16;
  uchar *hucp, *lucp, mask = 0, *eucp = &tiprangep->lolim[lth];
  int numbits = 0;
                                                   // step 1
  for (lucp = tiprangep->lolim, hucp = tiprangep->hilim;
    lucp < eucp && *lucp == *hucp;
    lucp++,  hucp++, numbits += 8);
  if (lucp < eucp)
    {
    for (mask = 0x80; mask && (mask & *lucp) == (mask & *hucp);
      mask >>= 1, numbits++);
       // at first difference. test remains of byte
    while(mask && !(mask & *lucp) && (mask & *hucp)) mask >>= 1;
    if (!mask) // now test remainder of bytes
      {
      for (lucp++, hucp++; lucp < eucp && !*lucp && *hucp == 0xff;
        lucp++, hucp++);
      }
    }
  uchar bitstring[18];
  int strlth;
  memset(bitstring, 0, sizeof(bitstring));
  clear_casn(&ipAddrOrRangep->self);
  if (!mask && lucp >= eucp)                // step 2
    {
    strlth = (numbits + 7) >> 3;
    memcpy(&bitstring[1], tiprangep->lolim, strlth);
    bitstring[0] = (8 - (numbits & 7)) & 7;
    write_casn(&ipAddrOrRangep->addressPrefix, bitstring, strlth + 1);
    }
                                                   // step 3
  else
    {
      // low end
    if (tiprangep->typ == IPv4) lucp = &tiprangep->lolim[3];
    else lucp = &tiprangep->lolim[15];
    while (lucp > (uchar *)&tiprangep->lolim && !*lucp) lucp--;
    strlth = (lucp - tiprangep->lolim) + 1;
    memcpy(&bitstring[1], tiprangep->lolim, strlth);
    for (bitstring[0] = 0, mask = *lucp; mask && !(mask & 1);
      mask >>= 1, bitstring[0]++);
    write_casn(&ipAddrOrRangep->addressRange.min, bitstring, strlth + 1);

      // high end
    if (tiprangep->typ == IPv4) lucp = &tiprangep->hilim[3];
    else lucp = &tiprangep->hilim[15];
    while (lucp > (uchar *)&tiprangep->hilim && *lucp == 0xFF) lucp--;
    strlth = (lucp - tiprangep->hilim) + 1;
    memcpy(&bitstring[1], tiprangep->hilim, strlth);
    lucp = &bitstring[strlth];
    for (bitstring[0] = 0, mask = 1; (mask & *lucp); mask <<= 1, bitstring[0]++)
      {
      *lucp &= ~(mask);
      }
    write_casn(&ipAddrOrRangep->addressRange.max, bitstring, strlth + 1);
    }
  }

static int expand(struct ipranges *rulerangesp, int numrulerange,
  struct ipranges *certrangesp, int numcertrange, int *changesp)
  {
/*
1. WHILE have rule
     IF have C, test R-hi touching C-lo
2.   IF have no C OR R-hi < C-lo
       Inject new C
       Set C-lo to R-lo
       Set C-hi to R-hi
       Get next rule
3.   ELSE IF R-hi just touches C-lo
       Set C-lo to R-lo
       IF C-hi >= R-hi, finished with this rule so get next rule
4.   ELSE ( R-hi > C-lo)
       IF C-hi doesn't touch R-lo
         Get next C
         Continue in WHILE
       IF C-lo > R-lo, set C-lo to R-lo
       IF R-hi > C-hi, 
         Set C-hi to R-hi
         Get next rule
     IF no rule, break out of WHILE
5.   Do C-hi
     IF R-hi <= C-hi
       Get next rule
     ELSE (R-hi > C-hi)
       IF C-hi touches R-lo, set C-hi to R-hi
       ELSE get next C
*/
  int did = 0;
  struct iprange *certrangep = &certrangesp->iprangep[numcertrange],
    *rulerangep = &rulerangesp->iprangep[numrulerange];
  int lth = rulerangep->typ == IPv6? 16: 4;
  int flag = 0, lastcert = numcertrange - 1;
  if ((locflags & RESOURCE_NOUNION)) flag = 1;
  while (rulerangep)                   // step 1
    {
    int ansr = -1;
    if (certrangep) ansr = touches(rulerangep, certrangep, lth);
    if (ansr < 0)                     // step 2
      {
      if (flag) return -1;
      certrangep = inject_range(certrangesp, ++lastcert);
      certrangep->typ = rulerangep->typ;
      memcpy(certrangep->lolim, rulerangep->lolim, lth);
      memcpy(certrangep->hilim, rulerangep->hilim, lth);
      rulerangep = next_range(rulerangesp, rulerangep);
      did++;
      if (!rulerangep) continue;
      }
    else if (!ansr)                  // step 3
      {
      if (flag) return -1;
      memcpy(certrangep->lolim, rulerangep->lolim, lth);
      if (memcmp(certrangep->hilim, rulerangep->hilim, lth) >= 0)
        rulerangep = next_range(rulerangesp, rulerangep);
      did++;
      }
    else     //   ansr > 0             step 4
      {
      if (touches(certrangep, rulerangep, lth) < 0)
        {
        lastcert = certrangep - certranges.iprangep;
        certrangep = next_range(certrangesp, certrangep);
        continue;
        }
      if (memcmp(certrangep->lolim, rulerangep->lolim, lth) > 0)
        {
        if (flag) return -1;
        memcpy(certrangep->lolim, rulerangep->lolim, lth);
        did++;
        }
      if (memcmp(rulerangep->hilim, certrangep->hilim, lth) > 0)
        {
        if (flag) return -1;
        memcpy(certrangep->hilim, rulerangep->hilim, lth);
        rulerangep = next_range(rulerangesp, rulerangep);
        did++;
        }
      }
    if (!rulerangep) break;
                                           // step 5
    if (memcmp(rulerangep->hilim, certrangep->hilim, lth) <= 0)
      {
      rulerangep = next_range(rulerangesp, rulerangep);
      did++;
      }
    else if ((ansr = touches(certrangep, rulerangep, lth)) >= 0)
      {
      if (flag) return -1;
      memcpy(certrangep->hilim, rulerangep->hilim, lth);
      lastcert = certrangep - certrangesp->iprangep;
      certrangep = next_range(certrangesp, certrangep);
      rulerangep = next_range(rulerangesp, rulerangep);
      }
    else 
      {
      lastcert = certrangep - certrangesp->iprangep;
      certrangep = next_range(certrangesp, certrangep);
      } 
    }
  return did;
  }

static int perforate(struct ipranges *rulerangesp, int numrulerange,
  struct ipranges *certrangesp, int numcertrange, int *changesp)
  {  // result = certranges - ruleranges
/*
Procedure:
   Starting at first rule (one guaranteed) and first cert field of this
     type (not guaranteed)
Notation: C is certificate item, C-lo is its low end, C-hi its high end
          R is rule item, R-lo is its low end, R-hi its high end
1. WHILE have C AND have R of this type
    IF C-hi < R-lo
      Get next C
      Start WHILE again
    IF C-lo > R-hi
      Get next R
      Start WHILE again
    Now C-lo <= R-hi AND C-hi >= R-lo
2.  IF C-lo < R-lo 
        IF C-hi <= R-hi
          Set C-hi = R-lo - 1.
          Get next cert
        ELSE (C-hi > R-hi) 
            Inject new C with C-lo = old C-lo AND C-hi = R-lo - 1
            Go to next C
            Set C-lo to R-hi + 1
            Get next R
3.  ELSE (C-lo >= R-lo) 
        IF C-hi <= R-hi, delete C
        ELSE (C-hi > R-hi) chop off low end of C
            Set C-lo = R-hi + 1 
            Get next R  
  Return index of last rule
*/
  struct iprange *certrangep = &certrangesp->iprangep[numcertrange],
    *rulerangep = &rulerangesp->iprangep[numrulerange];
  int did = 0, typ = certrangep->typ, lth = (typ == IPv6)? 16: 4;
                                                  // step 1
  while(certrangep && rulerangep)
    {
    if (memcmp(certrangep->hilim, rulerangep->lolim, lth) < 0)
      {
      certrangep= next_range(certrangesp, certrangep);
      continue;
      }
    if (memcmp(certrangep->lolim, rulerangep->hilim, lth) > 0)
      {
      rulerangep = next_range(rulerangesp, rulerangep);
      continue;
      }
                       // step 2
    if (memcmp(certrangep->lolim, rulerangep->lolim, lth) < 0)
      {
      if (memcmp(certrangep->hilim, rulerangep->hilim, lth) <= 0)
        {     // C-hi <= R-hi
        memcpy(certrangep->hilim, rulerangep->lolim, lth);
        decrement_iprange(certrangep->hilim, lth);
        certrangep = next_range(certrangesp, certrangep);
        }
      else // C-hi > R-hi
        {
        certrangep = inject_range(certrangesp, 
          certrangep - certrangesp->iprangep);
        memcpy(certrangep->lolim, certrangep[1].lolim, lth);
        memcpy(certrangep->hilim, rulerangep->lolim, lth);
        certrangep->typ = certrangep[1].typ;
        decrement_iprange(certrangep->hilim, lth);
        certrangep++;
        memcpy(certrangep->lolim, rulerangep->hilim, lth);
        increment_iprange(certrangep->lolim, lth);
        rulerangep = next_range(rulerangesp, rulerangep); 
        }
      did++;
      }
               // step 3
    else 
      {      // C-lo >= R-lo
      if (memcmp(certrangep->hilim, rulerangep->hilim, lth) <= 0)
        certrangep = eject_range(certrangesp, certrangep -
          certrangesp->iprangep);
      else
        {   // C-hi > R-hi
        memcpy(certrangep->lolim, rulerangep->hilim, lth);
        increment_iprange(certrangep->lolim, lth);
        rulerangep = next_range(rulerangesp, rulerangep); 
        }
      did++;
      }
    }
  *changesp = did;
  return did;
  }

static int perf_A_from_B(struct ipranges *lessp, struct ipranges *fromp)
  {
  int ansr, typ = IPv4, lessnum = 0, fromnum = 0, changes;
  if ((ansr = perforate(lessp, lessnum, fromp, fromnum, &changes)) < 0)
    return ansr;
  for (lessnum = 0; lessnum < lessp->numranges - 1 &&
    lessp->iprangep[lessnum].typ <= typ; lessnum++);
  for (fromnum = 0; fromnum < fromp->numranges - 1 &&
    fromp->iprangep[fromnum].typ <= typ; fromnum++);
  typ = IPv6;
  if (fromp->iprangep[fromnum].typ == typ &&
      lessp->iprangep[lessnum].typ == typ &&
      (ansr = perforate(lessp, lessnum, fromp, fromnum, &changes)) < 0)
    return ansr;
  for (lessnum = 0; lessnum < lessp->numranges - 1 &&
    lessp->iprangep[lessnum].typ <= typ; lessnum++);
  for (fromnum = 0; fromnum < fromp->numranges - 1 &&
    fromp->iprangep[fromnum].typ <= typ; fromnum++);
  typ = ASNUM;
  if (fromp->iprangep[fromnum].typ == typ &&
      lessp->iprangep[lessnum].typ == typ)
      ansr = perforate(lessp, lessnum, fromp, fromnum, &changes);
  return ansr;
  }

static void print_range(char *title, struct ipranges *rangesp)
  {
/*
  int i, j;
  fprintf(stderr, "%s\n", title);
  for (i = 0; i < rangesp->numranges; i++)
    {
    struct iprange *iprangep = &rangesp->iprangep[i];
    fprintf(stderr, "%d ", iprangep->typ);
    int lth;
    if (iprangep->typ == 4) lth = 4;
    else lth = 16;
    for (j = 0; j < lth; j++)
      fprintf(stderr, "0x%02x ", iprangep->lolim[j]);
    fprintf(stderr, "\n  ");
    for (j = 0; j < lth; j++)
      fprintf(stderr, "0x%02x ", iprangep->hilim[j]);
    fprintf(stderr, "\n");
    }
  fprintf(stderr, "\n");
*/
  }

static void copy_text(struct iprange *rulep, struct iprange *savp)
  {
  if (memcmp(rulep->lolim, savp->lolim, 16) <= 0 &&
      memcmp(rulep->hilim, savp->hilim, 16) >= 0)
    {
    savp->text = calloc(1, strlen(rulep->text) + 2);
    strcat(strcat(skibuf, rulep->text), " ");
    }
  }
 
static int conflict_test(int perf, struct done_cert *done_certp)
  {
/*
1. IF have done perforation and are now expanding (orig > para)
     Make fromrange out of origcert
     Make lessrange out of paracert
   ELSE have expanded and are nor perforating
     Make fromrange out of paracert
     Make lessrange out of origcert
2. Perforate fromrange with lessrange
3. Compare resulting fromrange with original rule list
   IF there is any overlap, error
   ELSE no error
*/
  int ansr;
  if (!perf)                        // step 1
    {
    mk_certranges(&fromranges, done_certp->origcertp);
    mk_certranges(&lessranges, done_certp->paracertp);
    }
  else
    {
    mk_certranges(&fromranges, done_certp->paracertp);
    mk_certranges(&lessranges, done_certp->origcertp);
    }
                                           // step 2
  print_range("From", &fromranges);
  print_range("Less", &lessranges);
  if ((ansr = perf_A_from_B(&lessranges, &fromranges)) < 0) return ansr;
                                             // step 3
  print_range("From", &fromranges);
  clear_ipranges(&lessranges);
  struct iprange *iprangep;
  int i;      // copy rules to less 
  for (i = 0; i < ruleranges.numranges; i++)
    {
    struct iprange *rulerangep = &ruleranges.iprangep[i];
    iprangep = inject_range(&lessranges, i);
    iprangep->typ = ruleranges.iprangep[i].typ;
    memcpy(iprangep->lolim, rulerangep->lolim, sizeof(iprangep->lolim));
    memcpy(iprangep->hilim, rulerangep->hilim, sizeof(iprangep->hilim));
    if (rulerangep->text)
      {
      iprangep->text = calloc(1, strlen(rulerangep->text));
      strcpy(iprangep->text, rulerangep->text);
      }
    }
  iprangep = inject_range(&lessranges,i);
  iprangep->typ = 0;
  memset(iprangep->lolim, 0, sizeof(iprangep->lolim));
  memset(iprangep->hilim, 0, sizeof(iprangep->hilim));
  struct ipranges savranges;         // save copy of fromrange
  savranges.numranges = 0;
  savranges.iprangep = (struct iprange *)0;
  int j;
              // save the present fromranges
  for (j = 0; j < fromranges.numranges; j++) 
    {
    struct iprange *siprangep, *fiprangep;
    inject_range(&savranges, j);
    siprangep = &savranges.iprangep[j];
    fiprangep = &fromranges.iprangep[j];
    siprangep->typ = fiprangep->typ;
    memcpy(siprangep->lolim, fiprangep->lolim, sizeof(fiprangep->lolim));   
    memcpy(siprangep->hilim, fiprangep->hilim, sizeof(fiprangep->hilim));
    } 
  print_range("Less", &lessranges);
  ansr = perf_A_from_B(&lessranges, &fromranges);
  print_range("From", &fromranges);
  if (ansr < 0) return ansr;
  if (fromranges.numranges > 1)  // "subtract"  new fromranges from old
    {
    perf_A_from_B(&fromranges, &savranges);  // diff shows where it occurred
      // find where
    int jj, k = 0;
    *skibuf = 0;
    struct iprange *savp;
    for (jj = 0;  jj < savranges.numranges; jj++)
      {
      int kk;
      savp = &savranges.iprangep[jj];
      if (savp->typ == IPv4)
        {
        for (kk = 0; ruleranges.iprangep[kk].typ == IPv4; kk++)
          {
          copy_text(&ruleranges.iprangep[kk], savp);
          }     
        k++;
        while(savranges.iprangep[jj].typ == IPv4) jj++;
        }
      else if (savranges.iprangep[jj].typ == IPv6)
        {
        for (  ; ruleranges.iprangep[kk].typ == IPv6; kk++)
          {
          copy_text(&ruleranges.iprangep[kk], savp);
          }     
        while(savranges.iprangep[jj].typ == IPv6) jj++;
        }
      else if (savranges.iprangep[jj].typ == ASNUM)
        {
        for (kk = 0; ruleranges.iprangep[kk].typ == IPv4; kk++)
          {
          copy_text(&ruleranges.iprangep[kk], savp);
          }     
        while(savranges.iprangep[jj].typ == ASNUM) jj++;
        }
      }
    ansr = 1;
    }
  else ansr = 0;
  free_ipranges(&fromranges);
  free_ipranges(&lessranges);
  return ansr;
  }

static int run_through_typlist(int run, int numrulerange, int numcertrange,
  int *changesp)
  {
/*
Function: Reads through list of addresses and cert extensions to expand or
perforate them.
inputs:  run: 0 = expand, 1 = perforate,
        index to first iprange of this typ.  At least one guaranteed
        index "   "  certrange "   "    " .  Not guaranteed
        Ptr to record changes
Returns: Index to next constraint beyond this type
Procedure:
1. IF expanding, expand cert
   ELSE IF have certificate items of this type, perforate them
   Reconstruct IP addresses in cert from ruleranges
   Note ending point in list
*/
  int did;
                                                  // step 1
  if (!run)
    {
    did = expand(&ruleranges, numrulerange, &certranges, numcertrange, 
      changesp);
    if (did < 0)
      {
      char *typname;
      if (ruleranges.iprangep[numrulerange].typ == IPv4) typname = "IPv4";
      else if (ruleranges.iprangep[numrulerange].typ == IPv6) typname = "IPv6";
      else typname = "AS#";
      log_msg(LOG_DEBUG, "Did not expand %s in block %s.", typname, currskibuf);
      did = 0;
      } 
    }
  else did = perforate(&ruleranges, numrulerange, &certranges, numcertrange, 
    changesp);
  return did;
  }

static void remake_cert_ranges(struct Certificate *paracertp)
  {
/*
Function: reconstructs extensions in paracert from (modified?) certranges
Procedure:
1. IF have an extension for IP addresses, empty it
2. IF have certranges for IPv4
     IF no such extension, add one
     Translate all IPv4 addresses in certrange to the cert's IPv4 space
3. IF have any ranges for IPv6
     IF no such extension, add one
     Translate all IPv6 addresses in certrange to the cert's IPv6 space
4. IF cert has an AS# extension, empty it
   IF have any ranges for AS#
     IF no such extension, add one
     Translate all AS numbers in certrange to the cert's AS number space
*/
  struct iprange *certrangep = certranges.iprangep;
  int num4 = 0, num6 = 0;
  struct Extension *extp = find_extn(paracertp, id_pe_ipAddrBlock, 0);
  struct Extensions *extsp = &paracertp->toBeSigned.extensions;
  struct IpAddrBlock *ipAddrBlockp;
  struct IPAddressFamilyA *ipfamp;
  struct AddressesOrRangesInIPAddressChoiceA *ipAddrOrRangesp = NULL;
  struct IPAddressOrRangeA *ipAddrOrRangep;
  int numfam = 0;
  uchar fambuf[2];
                                                 // step 1
  *fambuf = 0;
  if (extp)
    {
    int i;
    for (i = num_items(&extp->extnValue.ipAddressBlock.self); i > 0;
      eject_casn(&extp->extnValue.ipAddressBlock.self, --i));
    }
  if (certrangep->typ == IPv4)                    // step 2
    {
    if (!extp)
      {
      extp = (struct Extension *)inject_casn(&extsp->self,
        num_items(&extsp->self));   // at the end of extensions
      }            // rewrite objid because step 1 cleared it
    write_objid(&extp->extnID, id_pe_ipAddrBlock);
    ipAddrBlockp = &extp->extnValue.ipAddressBlock;
    ipfamp = (struct IPAddressFamilyA *)inject_casn(&ipAddrBlockp->self,
      numfam++);
    fambuf[1] = 1;
    write_casn(&ipfamp->addressFamily, fambuf, 2);
    ipAddrOrRangesp = &ipfamp->ipAddressChoice.addressesOrRanges;
    for (certrangep = certranges.iprangep; certrangep;
      certrangep = next_range(&certranges, certrangep), num4++)
      {
      ipAddrOrRangep = (struct IPAddressOrRangeA *)
        inject_casn(&ipAddrOrRangesp->self, num4);
      make_IPAddrOrRange(ipAddrOrRangep, certrangep);
      }
    }
                                                  // step 3
  if ((certrangep = &certranges.iprangep[num4])->typ == IPv6)
    {
    if (!extp)
      {
      extp = (struct Extension *)inject_casn(&extsp->self,
        num_items(&extsp->self));  // at the end of extensions
      }
    ipAddrBlockp = &extp->extnValue.ipAddressBlock;
    ipfamp = (struct IPAddressFamilyA *)inject_casn(&ipAddrBlockp->self,
      numfam++);
    fambuf[1] = 2;
    write_casn(&ipfamp->addressFamily, fambuf, 2);
    ipAddrOrRangesp = &ipfamp->ipAddressChoice.addressesOrRanges;
    for (; certrangep; certrangep = next_range(&certranges, certrangep), num6++)
      {
      ipAddrOrRangep = (struct IPAddressOrRangeA *)
        inject_casn(&ipAddrOrRangesp->self, num6);
      make_IPAddrOrRange(ipAddrOrRangep, certrangep);
      }

    }
                                                   // step 4
  if ((extp = find_extn(paracertp, id_pe_autonomousSysNum, 0)))
    {
    int i;
    for (i = num_items(
      &extp->extnValue.autonomousSysNum.asnum.asNumbersOrRanges.self); i > 0;
      eject_casn(&extp->extnValue.autonomousSysNum.asnum.asNumbersOrRanges.self,
       --i));
    }
  if ((certrangep = &certranges.iprangep[num4 + num6])->typ == ASNUM)
    {
    if (!extp)
      {
      extp = (struct Extension *)inject_casn(&extsp->self,
        num_items(&extsp->self));  // at the end of extensions
      }            // rewrite objid because step 1 cleared it
    write_objid(&extp->extnID, id_pe_autonomousSysNum);
    struct AsNumbersOrRangesInASIdentifierChoiceA *asNumbersOrRangesp =
      &extp->extnValue.autonomousSysNum.asnum.asNumbersOrRanges;
    for (num4 = 0; certrangep;
      certrangep = next_range(&certranges, certrangep), num4++)
      {
      struct ASNumberOrRangeA *asNumOrRangep;
      asNumOrRangep = (struct ASNumberOrRangeA *)
        inject_casn(&asNumbersOrRangesp->self, num4);
      make_ASnum(asNumOrRangep, certrangep);
      }
    }
/*
  locbufp = (char *)calloc(1, dump_size(&paracertp->self) + 2);
  dump_casn(&paracertp->self, locbufp);
  fprintf(stderr, locbufp); 
*/
  }

static int modify_paracert(int run,   struct Certificate *paracertp)
  {
/*
Function: Applies constraints to paracert
Inputs: number for enlarge (0) or perforate (>0)
        ptr to array of ranges
        number of ranges
        ptr to paracert
Returns: number of changes made
Procedure:
1. Enlarge or perforate paracertificate's IPv4 addresses
2. Enlarge or perforate paracertificate's IPv6 addresses
3. Enlarge or perforate paracertificate's AS numbers
   Return count of changes made. if any
*/
  int numcertrange = 0, numrulerange = 0, typ, changes = 0, did = 0;
    // start at beginning of SKI list and IPv4 family in certificate
  struct iprange *rulerangep = ruleranges.iprangep;   // beginning of SKI list
                                                // step 1
  if (!(locflags & RESOURCE_NOUNION) || run)
    {
    typ = IPv4;
    if (rulerangep->typ == typ &&
      (did = run_through_typlist(run, numrulerange, numcertrange,
      &changes)) < 0) return did;
    while(rulerangep->typ == typ) rulerangep++;
                                   // step 2
    typ = IPv6;
    struct iprange *certrangep;
    for (certrangep = certranges.iprangep;
        certrangep->typ && certrangep->typ < typ; certrangep++);
    numcertrange = (certrangep - certranges.iprangep);
    numrulerange = (rulerangep - ruleranges.iprangep);
    if (rulerangep->typ == typ &&
      (did = run_through_typlist(run, numrulerange, numcertrange,
        &changes)) < 0) return did;
    while(rulerangep->typ == typ) rulerangep++;
                                     // step 3
    typ = ASNUM;
    for (certrangep = certranges.iprangep;
        certrangep->typ && certrangep->typ < typ; certrangep++);
    numcertrange = (certrangep - certranges.iprangep);
    numrulerange = (rulerangep - ruleranges.iprangep);
    if (rulerangep->typ == typ  &&
      (did = run_through_typlist(run, numrulerange, numcertrange,
        &changes)) < 0) return did;
    remake_cert_ranges(paracertp);
    }
  did = sign_cert(paracertp);
  if (did < 0) return did;
  return changes;
  }

static int search_downward(struct Certificate *topcertp)
  {
/*
Function: Looks for any instances of ruleranges in the children of the cert
  and perforates them
Inputs: starting certificate
Procedure:
1.  Get topcert's SKI
    FOR each of its children
      Get child's AKI
      IF haven't done this cert already, make a temporary done_cert
      ELSE use the one we have
      Make a paracert just in case
2.    Punch out any listed resources
3.    IF it's a temporary cert
        IF there was any error OR nothing was done, free the cert
        ELSE add the cert & paracert to the done list
4.    IF something was done, call this function with this child
*/
  struct Extension *extp = find_extn(topcertp,
      id_subjectKeyIdentifier, 0);
  struct Certificate *childcertp;
  int ansr, numkid, numkids;
  char pSKI[64], cAKI[64], cSKI[64];
  format_aKI(pSKI, &extp->extnValue.subjectKeyIdentifier);

  // Get list of children having pSKI as their AKI
  struct cert_answers *cert_answersp =
    find_cert_by_aKI((char *)0, pSKI, locscmp, locconp);
  numkids = cert_answersp->num_ansrs;
  if (numkids <= 0) return 0;
  childcertp = (struct Certificate *)calloc(1, sizeof(struct Certificate));
  Certificate(childcertp, (ushort)0);
  struct cert_answers mycert_answers;
  save_cert_answers(&mycert_answers, cert_answersp);
                                                 // step 1
  for (ansr = numkid = 0; numkid < numkids && ansr >= 0; numkid++)
    {
    struct cert_ansr *cert_ansrp = &mycert_answers.cert_ansrp[numkid];
    if ((ansr = get_casn_file(&childcertp->self, cert_ansrp->fullname, 0)) < 0)
        return ERR_SCM_COFILE;
    extp = find_extn(childcertp, id_authKeyId, 0);
    memset(cAKI, 0, 64);
    format_aKI(cAKI, &extp->extnValue.authKeyId.keyIdentifier);
    extp = find_extn(childcertp, id_subjectKeyIdentifier, 0);
    format_aKI(cSKI, &extp->extnValue.subjectKeyIdentifier);
    if (strcmp(cAKI, pSKI) || !strcmp(cSKI, cAKI)) continue;
    struct done_cert *done_certp, done_cert;
    int have = 0;
    if (!(done_certp = have_already(cSKI)))
      {
      done_certp = &done_cert;
      fill_done_cert(done_certp, cSKI, cert_ansrp->filename, childcertp,
        cert_ansrp->local_id, cert_ansrp->flags);
      }
    else
      {
      have = 1;
      if ((done_certp->perf & WASPERFORATEDTHISBLK)) continue;
      }
                                                // step 2
    ansr = modify_paracert(1, done_certp->paracertp);
    done_certp->perf |= (WASPERFORATED | WASPERFORATEDTHISBLK);
    if (have == 0)   // it is a temporary done_cert
      {
      if (ansr <= 0)
        {
        delete_casn(&done_cert.origcertp->self);
        delete_casn(&done_cert.paracertp->self);
        }
      else
        {
        add_done_cert(&done_cert);
#ifdef DUMP_THEM
        dump_test_cert(&done_cert, 1);
#endif
        }
      }
    if (ansr > 0) ansr = search_downward(done_certp->origcertp);
    }
  free(mycert_answers.cert_ansrp);
  delete_casn(&childcertp->self);
  return ansr;
  }

static int process_trust_anchors()
  {
  struct cert_answers *cert_answersp = find_trust_anchors(locscmp, locconp);
  if (cert_answersp->num_ansrs < 0) return -1;
  int ansr = 0, numkids = cert_answersp->num_ansrs, numkid;
  struct Certificate *childcertp;
  childcertp = (struct Certificate *)calloc(1, sizeof(struct Certificate));
  Certificate(childcertp, (ushort)0);
  struct cert_answers mycert_answers;
  char cSKI[64];
  save_cert_answers(&mycert_answers, cert_answersp);
  struct Extension *extp;
  struct cert_ansr *cert_ansrp = &mycert_answers.cert_ansrp[0];
      // get them
  for (numkid = 0; numkid < numkids; numkid++, cert_ansrp++)
    {
    int i;
    struct done_cert *done_certp = &done_certs.done_certp[0];
    for (i = 0; i < done_certs.numcerts; i++, done_certp++)
      {    // break if we have seen it
      if (done_certp->origID == cert_ansrp->local_id) break;
      }   // then break if we found it
    if (i < done_certs.numcerts) break;
        // or if it is the LTA
    if (!strcmp(myrootfullname, cert_ansrp->fullname)) continue;
           // or if it is an ETA
    if ((ansr = get_casn_file(&childcertp->self, cert_ansrp->fullname, 0))
        < 0) return ERR_SCM_COFILE;
    if (!(extp = find_extn(childcertp, id_pe_ipAddrBlock, 0)) &&
        !(extp = find_extn(childcertp, id_pe_autonomousSysNum, 0)))
      continue;
    if (i >= done_certs.numcerts)
      {
      struct done_cert done_cert;
      extp = find_extn(childcertp, id_subjectKeyIdentifier, 0);
      format_aKI(cSKI, &extp->extnValue.subjectKeyIdentifier);
      fill_done_cert(&done_cert, cSKI, cert_ansrp->filename, childcertp,
        cert_ansrp->local_id, cert_ansrp->flags);
      sign_cert(done_cert.paracertp);
      add_done_cert(&done_cert);
      search_downward(done_cert.origcertp);
      }
    }
  return 0;
  }

static int process_control_block(struct done_cert *done_certp)
  {
/*
Function: processes an SKI block, including ancestors
Inputs: ptr to base cert
Returns: 0 if OK else error code
Procedure:
1. FOR each run until a self-signed certificate is done
     IF there's a conflict AND
       the conflict test returns error, return error code
     Modify paracert in accordance with run
2.   IF current cert is self-signed, break out of FOR
3.   Get the current cert's AKI
     Get that parent cert (and make paracert if necessaru)
4. FOR all other self-signed certificates, search downward perforating them
   Return 0
*/
                                              // step 1
  int run = 0;
  struct Extension *extp;
  struct done_cert *ndone_certp = (struct done_cert *)0;
  for (run = 0; 1; run++)
    {
    int ansr;
    if (((done_certp->perf & WASPERFORATED) && !run) ||
      ((done_certp->perf &WASEXPANDED) && run))
      {
      if (conflict_test(run, done_certp))
        {
        currskibuf[strlen(currskibuf) - 1] = 0; // trim CR
        sprintf(errbuf, "in block %s at %s", currskibuf, skibuf);
        *skibuf = 0;
        return ERR_SCM_USECONFLICT;
        }
      }
       // if resource_nounion, skip expanding
    if ((ansr = modify_paracert(run, done_certp->paracertp)) < 0)
      return ansr;
    done_certp->perf |= (!run)? (WASEXPANDED | WASEXPANDEDTHISBLK):
      (WASPERFORATED | WASPERFORATEDTHISBLK);
#ifdef DUMP_THEM
    dump_test_cert(done_certp, 1);
#endif
                                                  // step 2
    if (!diff_casn(&done_certp->origcertp->toBeSigned.issuer.self,
       &done_certp->origcertp->toBeSigned.subject.self)) break;
                                                        // step 3
    extp = find_extn(done_certp->origcertp, id_authKeyId, 0);
    format_aKI(skibuf, &extp->extnValue.authKeyId.keyIdentifier);
    if ((ansr = get_CAcert(skibuf, &ndone_certp)) < 0) return ansr;
    done_certp = ndone_certp;
    }
    // oldcert is at a self-signed cert
  // for all ss certs
  search_downward(done_certp->origcertp);
  return 0;
  }

static int process_control_blocks(FILE *SKI)
  {
/*
Function processes successive "SKI blocks" until EOF
Inputs: File descriptor for SKI file
        buffer having first SKI line
        pointer to certificate??
Procedure:
1. DO
     IF SKI entry not valid, return BADSKIBLOCK
     IF can't locate certificate having SKI with a valid chain to a
       trust anchor
       Return error
     Process the block
     Process the trust anchors with these constraints
   WHILE skibuf has anything
*/
  struct done_cert *done_certp;
  int ansr = 1;
  do
    {
    char *cc, *skip;
    for (skip = &skibuf[4]; *skip == ' '; skip++);
    for (cc = skip; *cc == ':' || (*cc >= '0' && *cc <= '9') ||
        ((*cc | 0x20) >= 'a' && (*cc | 0x20) <= 'f'); cc++);
    if ((cc - skip) != 59 || *cc > ' ') 
      {
      for (cc = skip; *cc != '\n'; cc++);
      if (*cc == '\n') *cc = 0;
      sprintf(errbuf, "Invalid SKI: %s", skip);
      return ERR_SCM_BADSKIBLOCK;
      }
    *cc = 0;
    if ((ansr = get_CAcert(skip, &done_certp)) < 0) 
      {
      sprintf(errbuf, "No file for SKI %s.", skip);
      return ansr;
      }
    ruleranges.numranges = 0;
    ruleranges.iprangep = (struct iprange *)0;
    if ((ansr = getSKIBlock(SKI, skibuf, sizeof(skibuf))) < 0)
      {
      cc = strchr(skibuf, (int)'\n');
      if (cc && *cc) *cc = 0;
      if (*errbuf) strcat(strcat(errbuf, "at "), skibuf);
      else sprintf(errbuf, "Invalid prefix/range %s", skibuf); 
      return ansr; // with error message in errbuf BADSKIBLOCK
      }    // otherwise skibuf has another SKI line or NULL

    if ((locflags & RESOURCE_NOUNION))
      {
      while (ruleranges.numranges) eject_range(&ruleranges, 0);
      int j;
      struct iprange *ciprangep;
      for (j = 0; j < certranges.numranges; j++)
        {
        struct iprange *riprangep = inject_range(&ruleranges, j);
        ciprangep = &certranges.iprangep[j];
        riprangep->typ = ciprangep->typ;
        memcpy(riprangep->lolim, ciprangep->lolim, sizeof(ciprangep->lolim));
        memcpy(riprangep->hilim, ciprangep->hilim, sizeof(ciprangep->hilim));
        if (ciprangep->text)
          {
          riprangep->text = calloc(1, strlen(ciprangep->text) + 2);
          strcpy(riprangep->text, ciprangep->text);
          }
        }
      }
    int err;

    err = process_control_block(done_certp);
    process_trust_anchors();
    clear_ipranges(&ruleranges);
    if (err < 0) return err;
    int i;
    for (done_certp = &done_certs.done_certp[i = 0]; i < done_certs.numcerts;
      done_certp++, i++)
      {
      done_certp->perf &= ~(WASPERFORATEDTHISBLK | WASEXPANDEDTHISBLK);
      }
    if (!*nextskibuf) break;
    strcpy(currskibuf, nextskibuf);
    strcpy(skibuf, nextskibuf);
    }
  while(ansr);
#ifdef DUMP_THEM
 dump_test_certs(1);  a diagnostic tool
#endif
  return 0;
  }

int read_SKI_blocks(scm *scmp, scmcon *conp, char *skiblockfile)
  {
/*
Procedure:
1. Call parse_SKI_blocks
2. Process all the control blocks
   IF no error,
     FOR each item in done_certs
       Flag the target cert in the database as having a para
       Sign the paracertificate
       Put it into database with para flag
   Free all and return error
*/
  Certificate(&myrootcert, (ushort)0);
  int numcert;
  int locansr = 0;
  char locfilename[128];
  *locfilename = 0;
  int ansr = 0;
                                                     // step 1
  FILE *SKI = fopen(skiblockfile, "r");
  log_msg(LOG_DEBUG, "Starting LTA work");
  if (!SKI) ansr = ERR_SCM_NOSKIFILE;
  else if ((ansr = parse_SKI_blocks(SKI, skibuf, sizeof(skibuf), &locflags))
     >= 0)
    {
    if (!Xcp)
      {
      Xcp = (char *)calloc(1,4);
      *Xcp = 'D';
      }
    strcpy(currskibuf, skibuf); 
    locscmp = scmp;
    locconp = conp;
    if (findorcreatedir(locscmp, locconp, Xrpdir, &XrpdirId) < 0)
      {
      sprintf(errbuf, "Cannot find directory %s.", Xrpdir);
      ansr = ERR_SCM_BADSKIFILE;
      }
    else ansr = process_control_blocks(SKI);
    }
  struct done_cert *done_certp = done_certs.done_certp;
  for (numcert = 0; numcert < done_certs.numcerts; numcert++, done_certp++)
    {
    if (ansr >= 0)
      {
      // mark done_certp->cert as having para
      done_certp->origflags |= SCM_FLAG_HASPARACERT;
      if (done_certp->perf & WASEXPANDED)
        done_certp->origflags |= SCM_FLAG_ISTARGET;
      // put done_certp->paracert in database with para flag and
      // flag original cert as having a paracert
      if (locansr >= 0 && (locansr = add_paracert2DB(done_certp)) < 0)
        {
	  log_msg(LOG_DEBUG, "%s ", done_certp->filename);
        strcpy(locfilename, done_certp->filename);
        *skibuf = 0;
        }
      }
    delete_casn(&done_certp->origcertp->self);
    delete_casn(&done_certp->paracertp->self);
    free(done_certp->origcertp);
    free(done_certp->paracertp);
    }
  if (!ansr) *skibuf = 0;
  if (!ansr) ansr = locansr;
  if (SKI) fclose(SKI);
  delete_casn(&myrootcert.self);
  if (Xcp) free(Xcp);
  if (Xaia) free(Xaia);
  free(Xcrldp);
  free_keyring();
  if (*errbuf)
    {
    if (errbuf[strlen(errbuf) - 1] != '.' &&
      errbuf[strlen(errbuf) - 1] != '\n') strcat(errbuf, "."); 
    log_msg(LOG_ERR, "%s", errbuf);
    }
  log_msg(LOG_DEBUG, "Finished LTA work");
  return ansr;
  }

