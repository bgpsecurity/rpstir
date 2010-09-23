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

#define TREEGROWTH          1
#define RESOURCE_NOUNION    2
#define INTERSECTION_ALWAYS 4
#define PARACERT           64
// spares for afterthoughts
#define WASEXPANDED           128
#define WASPERFORATED         256
#define WASEXPANDEDTHISBLK    512
#define WASPERFORATEDTHISBLK 1024
#define SKIBUFSIZ         128

#define IPv4 4
#define IPv6 6
#define ASNUM 8

struct done_cert
  {
  char ski[64];
  int perf;      // see #defines in rpwork.c
  ulong origID, origflags;
  char filename[PATH_MAX];
  struct Certificate *origcertp, *paracertp;
  };

struct done_certs
  {
  int numcerts;
  struct done_cert *done_certp;
  };

static struct done_certs done_certs;

static int  locflags = 0;
static char skibuf[SKIBUFSIZ];
static char Xvalidity_dates[40];
static scm *locscmp;
static scmcon *locconp;
static struct Certificate myrootcert;
static struct ipranges certranges, ruleranges;

static char *Xcrldp;

static char *Xcp;

static char *Xrpdir;

#include <fcntl.h>

static struct casn *get_subject_name(struct Name *subjp)
  {
  struct RelativeDistinguishedName *rdnp = (struct RelativeDistinguishedName *)
      member_casn(&subjp->rDNSequence.self, 0);
  struct AttributeValueAssertion *avap = (struct AttributeValueAssertion *)
      member_casn(&rdnp->self, 0);
  struct DirectoryString *dirsp = &avap->value.commonName;
  struct casn *casnp = &dirsp->printableString;
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
/*
  sprintf(locbuf, "paracert%d.cer", ffindex++);
  put_casn_file(&done_certp->paracertp->self, locbuf, 0);
*/
  }

static void dump_test_certs(int orig)
  {
  int num;
  for (num = 0; num < done_certs.numcerts; num++)
    {
    dump_test_cert(&done_certs.done_certp[num], orig);
    }
  }
 
static char *nextword(char *cc)
  {
  char *b = strchr(cc, (int)' ');
  if (b) while (*b && *b == ' ') b++;
  return b;
  }

static int check_cp(char *cpp)
  {
  if ((*cpp == 'C' || *cpp == 'D' || *cpp == 'R') && cpp[1] <= ' ')
    {

    Xcp = (char *)calloc(1, 2);
    *Xcp = *cpp;
    }
  else
    {
    struct casn oid;
    tagged_constructor(&oid, 0, ASN_OBJ_ID, ASN_OBJ_ID);
    int ansr = write_objid(&oid, cpp);
    clear_casn(&oid);
    if (ansr > 0)
      {
      Xcp = (char *)calloc(1, strlen(cpp) + 2);
      strcpy(Xcp, cpp);
      }
    else return -1;
    }
  return 1;
  }

static char *Xaia;

static struct validity_dates
  {
  struct casn lodate;
  struct casn hidate;
  } Xvaliddates;

static int check_date(char *datep, struct casn *casnp)
  {
  char *c;
  for (c = datep; *c >= '0' && *c <= '9'; c++);
  if (*c != 'Z' || c != &datep[14]) return -1;
  if (strncmp(datep, "2000", 4) < 0) return -1;
  ulong tag;
  if (strncmp(datep, "2050", 4) >= 0) tag = (ulong)ASN_GENTIME;
  else tag = (ulong)ASN_UTCTIME;
  tagged_constructor(casnp, 0, tag, tag);
  if ((tag == (ulong)ASN_UTCTIME &&
    (write_casn(casnp, (uchar *)&datep[2], 13) < 0 ||
    read_casn_time(casnp, &tag)) < 0) ||
    (tag == (ulong)ASN_GENTIME &&
    (write_casn(casnp, (uchar *)datep, 15) < 0 ||
    read_casn_time(casnp, &tag) < 0))) return -1;
  return 1;
  }

static int check_dates(char *datesp)
  {
  char *enddatep = nextword(datesp);
  if (!enddatep || datesp[14] != 'Z' || datesp[15] != ' ' ||
    enddatep[14] != 'Z' || enddatep[15] > ' ' ||
    strncmp(datesp, enddatep, 14) >= 0) return -1;
  if (check_date(datesp, &Xvaliddates.lodate) < 0 ||
    check_date(enddatep, &Xvaliddates.hidate) < 0) return -1;
  return 1;
  }

struct keyring
  {
  char *filename;
  char *label;
  char *password;
  };

static struct keyring keyring;

static int check_keyring(char *cc)
  {
  char *b;
  if ((cc = nextword(cc)))
    {
    b = strchr(cc, (int)' ');
    if (b)
      {
      keyring.filename = (char *)calloc(1, (b - cc) + 2);
      strncpy(keyring.filename, cc, (b - cc));
      if ((cc = nextword(cc)))
        {
        if ((b = strchr(cc, (int)' ')))
          {
          keyring.label = (char *)calloc(1, (b - cc) + 2);
          strncpy( keyring.label, cc, (b - cc));
          if ((cc = nextword(cc)))
            {
            for (b = cc; *b > ' '; b++);
            keyring.password = (char *)calloc(1, (b - cc) + 2);
            strncpy( keyring.password, cc, (b - cc));
            return 1;
            }
          }
        }
      }
    }
  return -1;
  }

static void free_keyring(struct keyring *ringp)
  {
  if (ringp->filename) free(ringp->filename);
  if (ringp->label) free(ringp->label);
  if (ringp->password) free(ringp->password);
  ringp->filename = ringp->label = ringp->password = (char *)0;
  }

static int add_done_cert(char *skip, struct Certificate *origcertp,
  struct Certificate *paracertp, int flags, int local_id, char *filename)
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
  strcpy(done_certp->ski, skip);
  done_certp->origID = local_id;
  done_certp->origflags = flags;
  done_certp->origcertp = origcertp;
  done_certp->paracertp = paracertp;
  strcpy(done_certp->filename, filename);
  return done_certs.numcerts - 1;
  }

static struct Extension *find_extension(struct Certificate *certp, char *oid,
  int add)
  {
  struct Extensions *extsp = &certp->toBeSigned.extensions;
  struct Extension *extp;
  int num = num_items(&extsp->self);
  if (!num && !add) return (struct Extension *)0;
  for (extp = (struct Extension *)member_casn(&extsp->self, 0);
    extp && diff_objid(&extp->extnID, oid);
    extp = (struct Extension *)next_of(&extp->self));
  if (!extp && add)
    {
    extp = (struct Extension *)inject_casn(&extsp->self, num);
    }
  return extp;
  }

static void free_ipranges(struct ipranges *iprangesp)
  {
  int i;
  struct iprange *iprangep = iprangesp->iprangep;
  if (!iprangep) return;
  for (i = 0; i < iprangesp->numranges; i++, iprangep++)
    {
    if (iprangep->text) free(iprangep->text);
    }
  free(iprangesp->iprangep);
  iprangesp->iprangep = (struct iprange *)0;
  }

static void clear_ipranges(struct ipranges *iprangesp)
  {
  free_ipranges(iprangesp);
  iprangesp->iprangep = (struct iprange *)0;
  iprangesp->numranges = 0;
  }

static void internal_error(char *msg)
  {
  fprintf(stderr, msg);
  exit(0);
  }

static struct iprange *eject_range(struct ipranges *iprangesp, int num)
  {
  if (num < 0 || num >= iprangesp->numranges)
    internal_error("Ejecting out of range\n");
  iprangesp->numranges--;
  struct iprange *newrangep = (struct iprange *)calloc(
    iprangesp->numranges, sizeof(struct iprange));
  int i;
  for(i = 0; i < num; i++)
    {
    newrangep[i].typ = iprangesp->iprangep[i].typ;
    memcpy(newrangep[i].lolim, iprangesp->iprangep[i].lolim, 18);
    memcpy(newrangep[i].hilim, iprangesp->iprangep[i].hilim, 18);
    newrangep[i].text = iprangesp->iprangep[i].text;
    }
  for( ; i < iprangesp->numranges; i++)
    {
    newrangep[i].typ = iprangesp->iprangep[i + 1].typ;
    memcpy(newrangep[i].lolim, iprangesp->iprangep[i + 1].lolim, 18);
    memcpy(newrangep[i].hilim, iprangesp->iprangep[i + 1].hilim, 18);
    newrangep[i].text = iprangesp->iprangep[i + 1].text;
    }
  free_ipranges(iprangesp);
  iprangesp->iprangep = newrangep;
  return &iprangesp->iprangep[num];
  }

static struct iprange *inject_range(struct ipranges *iprangesp, int num)
  {
  if (num < 0 || num > iprangesp->numranges)
    internal_error("Injecting out of range\n");
  struct iprange *newrangep = (struct iprange *)calloc(
    iprangesp->numranges + 1, sizeof(struct iprange));
  int i;
  for(i = 0; i < num; i++)
    {
    newrangep[i].typ = iprangesp->iprangep[i].typ;
    memcpy(newrangep[i].lolim, iprangesp->iprangep[i].lolim, 18);
    memcpy(newrangep[i].hilim, iprangesp->iprangep[i].hilim, 18);
    newrangep[i].text = iprangesp->iprangep[i].text;
    }
  memset(newrangep[i].lolim, 0, sizeof(newrangep));
  memset(newrangep[i].hilim, 0, sizeof(newrangep));
  newrangep[i].text = 0;
  for( ; i < iprangesp->numranges; i++)
    {
    newrangep[i + 1].typ = iprangesp->iprangep[i].typ;
    memcpy(newrangep[i + 1].lolim, iprangesp->iprangep[i].lolim, 18);
    memcpy(newrangep[i + 1].hilim, iprangesp->iprangep[i].hilim, 18);
    newrangep[i + 1].text = iprangesp->iprangep[i].text;
    }
  free_ipranges(iprangesp);
  iprangesp->numranges++;
  iprangesp->iprangep = newrangep;
  return &iprangesp->iprangep[num];
  }

static struct iprange *next_range(struct ipranges *iprangesp,
  struct iprange *iprangep)
  {
  if (iprangep[1].typ != iprangep->typ) return (struct iprange *)0;
  return ++iprangep;
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
  sprintf(fullname, "%s/%s", Xrpdir, done_certp->filename);
  if ((ansr = put_casn_file(&done_certp->paracertp->self, fullname, 0)) < 0)
    return ansr;
  ansr = add_object(locscmp, locconp, done_certp->filename, Xrpdir, fullname,
     0);
  if (ansr >= 0) 
    { 
    flags = done_certp->origflags & ~(SCM_FLAG_NOCHAIN);
    struct Extension *extp = find_extension(done_certp->paracertp,
      id_subjectKeyIdentifier, 0);
    format_aKI(ski, &extp->extnValue.subjectKeyIdentifier);
    cert_answersp = find_cert_by_aKI(ski, (char *)0, locscmp, locconp);
    if (!cert_answersp && cert_answersp->num_ansrs < 0) return -1;
    ansr = cert_answersp->num_ansrs;
    if (ansr < 0) return ansr;
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
    flags &= ~(SCM_FLAG_HASPARACERT);
    ansr = set_cert_flag(locconp, cert_ansrp->local_id, flags);
    fprintf(stderr, "Added %s to DB\n", fullname);
    return 1;
    }
  else fprintf(stderr, "Adding %s to DB failed with error %d\n", fullname,
    -ansr); 
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
        &ipAddrBlock->self, 0);  1;
    ipFamp = (struct IPAddressFamilyA *)next_of(&ipFamp->self))
    {
    read_casn(&ipFamp->addressFamily, fambuf);
    if (fambuf[1] == loctyp)  // OK the cert has some
     return &ipFamp->ipAddressChoice.addressesOrRanges;
    }
  return (struct AddressesOrRangesInIPAddressChoiceA *)0;
  }

static void mk_certranges(struct Certificate *certp)
  {
  if (certranges.numranges > 0 || certranges.iprangep)
      clear_ipranges(&certranges);
  struct Extension *extp = find_extension(certp, id_pe_ipAddrBlock, 0);
  int num;
  struct AddressesOrRangesInIPAddressChoiceA *ipAddrOrRangesp =
    find_IP(IPv4, extp);
  struct IPAddressOrRangeA *ipAddrOrRangep = (struct IPAddressOrRangeA *)
    member_casn(&ipAddrOrRangesp->self, 0);
  struct iprange *certrangep;
  for (num = 0; ipAddrOrRangep; ipAddrOrRangep = (struct IPAddressOrRangeA *)
    next_of(&ipAddrOrRangep->self))
    {
    certrangep = inject_range(&certranges, num++);
    certrangep->typ = IPv4;
    cvt_asn(certrangep, ipAddrOrRangep);
    }
  ipAddrOrRangesp = find_IP(IPv6, extp);
  for (ipAddrOrRangep = (struct IPAddressOrRangeA *)
    member_casn(&ipAddrOrRangesp->self, 0);
    ipAddrOrRangep; ipAddrOrRangep = (struct IPAddressOrRangeA *)
    next_of(&ipAddrOrRangep->self))
    {
    certrangep = inject_range(&certranges, num++);
    certrangep->typ = IPv6;
    cvt_asn(certrangep, ipAddrOrRangep);
    }
  extp = find_extension(certp, id_pe_autonomousSysNum, 0);
  struct AsNumbersOrRangesInASIdentifierChoiceA *asNumbersOrRangesp =
    &extp->extnValue.autonomousSysNum.asnum.asNumbersOrRanges;
  struct ASNumberOrRangeA *asNumOrRangep;
  for (asNumOrRangep = (struct ASNumberOrRangeA *)
    member_casn(&asNumbersOrRangesp->self, 0); asNumOrRangep;
    asNumOrRangep = (struct ASNumberOrRangeA *)next_of(&asNumOrRangep->self))
    {
    certrangep = inject_range(&certranges, num++);
    certrangep->typ = ASNUM;
    cvt_asnum(certrangep, asNumOrRangep);
    }
  certrangep = inject_range(&certranges, num++);
  certrangep->typ = 0;
  }

static int snum_sfx;

static struct Certificate *mk_paracert(struct Certificate *origcertp)
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
  if (!Xcrldp || (*Xcrldp == 'R' && !Xcrldp[1]))
    {
    fextp = find_extension(&myrootcert, id_cRLDistributionPoints, 0);
    textp = find_extension(paracertp, id_cRLDistributionPoints, 1);
    copy_casn(&textp->self, &fextp->self);
    }
  else
    {
    textp = find_extension(paracertp, id_cRLDistributionPoints, 1);
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
        sprintf(skibuf, "Too many CRLDP extensions");
        return (struct Certificate *)0;
        }
      struct GeneralName *gennamep = (struct GeneralName *) inject_casn(
        &distp->distributionPoint.fullName.self, 0);
      if (!gennamep)
        {
        sprintf(skibuf, "Too many general names in CRLDP extensions");
        return (struct Certificate *)0;
        }
      for (ept = pt; *ept > ' '; ept++);
      write_casn(&gennamep->url, (uchar *)pt, ept - pt);
      }
    }
  if (Xcp && *Xcp != 'C')
    {
    textp = find_extension(paracertp, id_certificatePolicies, 1);
    if (*Xcp == 'R')
      {
      fextp = find_extension(&myrootcert, id_certificatePolicies, 0);
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
  if (Xaia && *Xaia != 'C' && Xaia[1] > 0)
    {
    textp = find_extension(paracertp, id_pkix_authorityInfoAccess, 1);
    clear_casn(&textp->extnValue.self);
    write_objid(&textp->extnID, id_pkix_authorityInfoAccess);
    struct AccessDescription *adp = (struct AccessDescription *)inject_casn(
      &textp->extnValue.authorityInfoAccess.self, 0);
    write_objid(&adp->accessMethod, id_ad_caIssuers);
    write_casn(&adp->accessLocation.url, (uchar *)Xaia, strlen(Xaia));
    }
  struct Extension *skiExtp, // root's ski
        *akiExtp;   // new cert's aki
  if (!(skiExtp = find_extension(&myrootcert, id_subjectKeyIdentifier, 0)))
    {
    // print message?
    return (struct Certificate *)0;
    }
  if (!(akiExtp = find_extension(paracertp, id_authKeyId, 1)))
    {
    // print message?
    return (struct Certificate *)0;
    }
  copy_casn(&akiExtp->extnValue.authKeyId.keyIdentifier,
      &skiExtp->extnValue.subjectKeyIdentifier);
  mk_certranges(paracertp);
  return paracertp;
  }

static int get_CAcert(char *ski, struct done_cert **done_certpp)
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
    for (cert_ansrp = &cert_answersp->cert_ansrp[0]; 
      i < cert_answersp->num_ansrs; i++, cert_ansrp++)
      {      // if it's a paracert, skip it 
      if (!strcmp(cert_ansrp->dirname, Xrpdir)) continue;
      certp = (struct Certificate *)calloc(1, sizeof(struct Certificate));
      Certificate(certp, (ushort)0);
      if ((ansr = get_casn_file(&certp->self, cert_ansrp->fullname, 0)) < 0)
        return ERR_SCM_COFILE;
      this_cert_ansrp = cert_ansrp;
      j++;
      }
    if (j != 1) 
      {
      if (!j) strcpy(skibuf, "No CA certificate found\n");
      else sprintf(skibuf, "%d certificates found\n", j); 
      return -1;
      } 
    struct Certificate *paracertp = mk_paracert(certp);
    if (!paracertp) ansr = ERR_SCM_BADSKIFILE;
    else if ((ansr = add_done_cert(ski, certp, paracertp, this_cert_ansrp->flags,
      this_cert_ansrp->local_id, this_cert_ansrp->filename)) >= 0)
      {
      done_certp = &done_certs.done_certp[ansr];
      if (!done_certp->paracertp) ansr =  ERR_SCM_BADPARACERT;
      else *done_certpp = done_certp;
      }
    free(cert_answersp->cert_ansrp);
    cert_answersp->num_ansrs = 0;
    cert_answersp->cert_ansrp = NULL;
    if (ansr < 0) return ansr;
    i = 1;
    }
  return i;
  }

static int getIPBlock(FILE *SKI, int typ)
  {
  char *c;
  while((c = fgets(skibuf, sizeof(skibuf), SKI)))
    {
    if ((typ == IPv4 && *skibuf == 'I') || (typ == IPv6 && *skibuf == 'A') ||
      (typ == ASNUM && *skibuf == 'S')) break;
    struct iprange *iprangep  = inject_range(&ruleranges, ruleranges.numranges);
    if (txt2loc(typ, skibuf, iprangep) < 0) return ERR_SCM_BADRANGE;
    if (!c) *skibuf = 0;
    }
  return (c)? 1: 0;
  }

static int getSKIBlock(FILE *SKI)
  {
  int ansr = ERR_SCM_BADSKIBLOCK;
  if (!fgets(skibuf, sizeof(skibuf), SKI) || strcmp(skibuf, "IPv4\n"))
    strcpy(skibuf, "Missing IPv4");
  else if (getIPBlock(SKI, IPv4) < 0)
    strcpy(skibuf, "Bad IPv4 group");
  else if (strcmp(skibuf, "IPv6\n"))
    strcpy(skibuf, "Missing IPv6");
  else if (getIPBlock(SKI, IPv6) < 0)
    strcpy(skibuf, "Bad IPv6 group");
  else if (strcmp(skibuf, "AS#\n"))
    strcpy(skibuf, "Missing AS#");
  else if((ansr = getIPBlock(SKI, ASNUM)) < 0)
    strcpy(skibuf, "Bad AS# group");
  else if (ruleranges.numranges == 0)
    strcpy(skibuf, "Empty SKI block");
  else ansr = 0;
  return ansr;
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
  uchar *hucp, *lucp, mask, *eucp = &tiprangep->lolim[lth];
  int numbits = 0;
                                                   // step 1
  for (lucp = tiprangep->lolim, hucp = tiprangep->hilim;
    lucp < eucp && *lucp == *hucp;
    lucp++,  hucp++, numbits += 8);
  if (lucp < eucp)
    {
    for (mask = 0x80; mask && (mask & *lucp) == (mask & *hucp);
      mask >>= 1, numbits++);
    }
       // at first difference. test remains of byte
  while(mask && !(mask & *lucp) && (mask & *hucp)) mask >>= 1;
  if (!mask) // now test remainder of bytes
    {
    for (lucp++, hucp++; lucp < eucp && !*lucp && *hucp == 0xff;
      lucp++, hucp++);
    }
  uchar bitstring[18];
  int strlth;
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
    for (bitstring[0] = 0, mask = *lucp; !(mask & 1);
      mask >>= 1, bitstring[0]++);
    write_casn(&ipAddrOrRangep->addressRange.min, bitstring, strlth + 1);

      // high end
    if (tiprangep->typ == IPv4) lucp = &tiprangep->hilim[3];
    else lucp = &tiprangep->hilim[15];
    while (lucp > (uchar *)&tiprangep->hilim && *lucp == 0xFF) lucp--;
    strlth = (lucp - tiprangep->hilim) + 1;
    memcpy(&bitstring[1], tiprangep->hilim, strlth);
    mask = (*lucp >> 1);
    bitstring[strlth] &= ~mask;
    for (bitstring[0] = 0; (mask & 1); mask >>= 1, bitstring[0]++);
    write_casn(&ipAddrOrRangep->addressRange.max, bitstring, strlth + 1);
    }
  }

static int touches(struct iprange *lop, struct iprange *hip, int lth)
  {
  struct iprange mid;
  memcpy(mid.lolim, lop->hilim, lth);
  increment_iprange(mid.lolim, lth);
  return memcmp(mid.lolim, hip->lolim, lth);
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
       Go back to original C
       Get next rule
3.   ELSE IF R-hi just touches C-lo
       Set C-lo to R-lo
       Get next rule
4.   ELSE ( R-hi > C-lo)
       IF C-lo > R-lo, set C-lo to R-lo
     IF no rule, break out of WHILE
5.   Do C-hi
     IF R-hi <= C-hi
       Get next rule
     ELSE (R-hi > C-hi)
       Set C-hi to R-hi
*/
  int did = 0;
  struct iprange *certrangep = &certrangesp->iprangep[numcertrange],
    *rulerangep = &rulerangesp->iprangep[numrulerange];
  int lth = rulerangep->typ == IPv6? 16: 4;

  while (rulerangep)                   // step 1
    {
    int ansr = -1;
    if (certrangep) ansr = touches(rulerangep, certrangep, lth);
    if (ansr < 0)                     // step 2
      {
      certrangep = inject_range(&certranges, certrangep - certranges.iprangep);
      certrangep->typ = rulerangep->typ;
      memcpy(certrangep->lolim, rulerangep->lolim, lth);    
      memcpy(certrangep->hilim, rulerangep->hilim, lth);
      certrangep++; 
      rulerangep = next_range(&ruleranges, rulerangep);
      did++;
      if (!rulerangep) continue;
      }
    else if (!ansr)                  // step 3
      {
      memcpy(certrangep->lolim, rulerangep->lolim, lth);
      rulerangep = next_range(&ruleranges, rulerangep);
      did++;
      }
    else     //   ansr > 0             step 4
      if (memcmp(certrangep->lolim, rulerangep->lolim, lth) > 0)
        memcpy(certrangep->lolim, rulerangep->lolim, lth);
    if (!rulerangep) break;
                                           // step 5
    if (memcmp(rulerangep->hilim, certrangep->hilim, lth) <= 0)
      {
      rulerangep = next_range(&ruleranges, rulerangep);
      did++;
      }
    else memcpy(certrangep->hilim, rulerangep->lolim, lth);
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
1. WHILE have C and C-hi < R-lo, get next C
2. WHILE have C AND have R of this type
2a    Check low ends
      IF C-lo < R-lo (R cuts off low end of C)
        Insert a new C before this one
        Set new C-lo to this C-lo
        Set new C-hi to R-lo - 1
        Set this C-lo to R-lo
2b    Check upper limits
      IF C-hi < R-hi (C ends before R)
        Delete C (gets next C)
      ELSE IF C-hi == R-hi (C ends at R)
        Delete C (gets next C)
        Get next R
      ELSE (C-hi > R-hi)
        IF C-lo <= R-hi AND R-hi more than touches C-lo
            Set C-lo to R-hi + 1 (Cut off bottom of C)
        Get next R
  Return index of last rule
*/
  struct iprange *certrangep = &certrangesp->iprangep[numcertrange],
    *rulerangep = &rulerangesp->iprangep[numrulerange];
  int did = 0, typ = certrangep->typ, lth = (typ == IPv6)? 16: 4;
                                                  // step 1
  while(certrangep &&
      memcmp(certrangep->hilim, rulerangep->lolim, lth) < 0)
      {
      certrangep = next_range(&certranges, certrangep);
      numcertrange++;
      }
                                                   // step 2
  while (certrangep && rulerangep)
    {
                                               // step 2a
    if (memcmp(certrangep->lolim, rulerangep->lolim, lth) < 0)
      {
      certrangep = inject_range(&certranges, numcertrange);
      certrangep->typ = typ;
      memcpy(certrangep->lolim, certrangep[1].lolim, lth);
      memcpy(certrangep->hilim, rulerangep->lolim, lth);
      decrement_iprange(certrangep->hilim, lth);
      certrangep++;
      memcpy(certrangep->lolim, rulerangep->lolim, lth);
      did++;
      }
                                                    // step 2b
    if (memcmp(certrangep->hilim, rulerangep->hilim, lth) < 0)
      {
      certrangep = eject_range(&certranges, numcertrange);
      did++;
      }
    else if (memcmp(certrangep->hilim, rulerangep->hilim, lth) == 0)
      {
      certrangep = eject_range(&certranges, numcertrange);
      rulerangep = next_range(&ruleranges, rulerangep);
      did++;
      }
    else // C-hi > R-hi
      {
      if (memcmp(certrangep->lolim, rulerangep->hilim, lth)  <= 0 &&
        touches(rulerangep, certrangep, lth) > 0)
        {
        memcpy(certrangep->lolim, rulerangep->hilim, lth);
        increment_iprange(certrangep->lolim, lth);
        did++;
        }
      rulerangep = next_range(&ruleranges, rulerangep);
      }
    }
  *changesp = did;
  return did;
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
  if (!run) did = expand(&ruleranges, numrulerange, &certranges, numcertrange, changesp);
  else did = perforate(&ruleranges, numrulerange, &certranges, numcertrange, changesp);
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
  struct Extension *extp = find_extension(paracertp, id_pe_ipAddrBlock, 0);
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
  if ((extp = find_extension(paracertp, id_pe_autonomousSysNum, 0)))
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
    sprintf(skibuf, "Error %s\n", msg);
    fflush(stderr);
    }
  return ansr;
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
  struct Extension *extp = find_extension(topcertp,
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
  mycert_answers.num_ansrs = numkids;
  mycert_answers.cert_ansrp = (struct cert_ansr *)
    calloc(numkids, sizeof(struct cert_ansr)); 
  for (numkid = 0; numkid < numkids; numkid++)
    {
    mycert_answers.cert_ansrp[numkid] = cert_answersp->cert_ansrp[numkid];
    }                                           // step 1
  for (ansr = numkid = 0; numkid < numkids && ansr >= 0; numkid++)
    {
    struct cert_ansr *cert_ansrp = &mycert_answers.cert_ansrp[numkid];
    if ((ansr = get_casn_file(&childcertp->self, cert_ansrp->fullname, 0)) < 0)
        return ERR_SCM_COFILE;
    extp = find_extension(childcertp, id_authKeyId, 0);
    memset(cAKI, 0, 64); 
    format_aKI(cAKI, &extp->extnValue.authKeyId.keyIdentifier);
    extp = find_extension(childcertp, id_subjectKeyIdentifier, 0);
    format_aKI(cSKI, &extp->extnValue.subjectKeyIdentifier);
    if (strcmp(cAKI, pSKI) || !strcmp(cSKI, cAKI)) continue;
    struct done_cert *done_certp, done_cert;
    int have = 0;
    if (!(done_certp = have_already(cSKI)))
      {
      done_certp = &done_cert;
      strcpy(done_cert.ski, cSKI);
      strcpy(done_cert.filename, cert_ansrp->filename);
      done_cert.origcertp = (struct Certificate *)
      calloc(1, sizeof(struct Certificate));
      Certificate(done_cert.origcertp, (ushort)0);
      copy_casn(&done_cert.origcertp->self, &childcertp->self);
      done_cert.origID = cert_ansrp->local_id;
      done_cert.origflags = cert_ansrp->flags;
      done_cert.paracertp =  mk_paracert(childcertp);
      done_cert.perf = 0;
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
        delete_casn(&done_certp->origcertp->self);
        delete_casn(&done_certp->paracertp->self);
        }
      else 
        {
        add_done_cert(done_cert.ski, done_cert.origcertp,
          done_cert.paracertp, done_cert.origflags, done_cert.origID, 
          done_cert.filename);
//        dump_test_cert(&done_cert, 1);
        }
      }
    if (ansr > 0) ansr = search_downward(done_certp->origcertp);
    }
  free(mycert_answers.cert_ansrp); 
  return ansr;
  }

static int process_control_block(struct done_cert *done_certp)
  {
/*
Function: processes an SKI block, including ancestors
Inputs: ptr to base cert
Returns: 0 if OK else error code
Procedure:
1. FOR each run until a self-signed certificate is done
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
    if (done_certp->perf && !run) return ERR_SCM_USECONFLICT;
    if ((ansr = modify_paracert(run, done_certp->paracertp)) < 0)
      return ansr;
    done_certp->perf |= (!run)? (WASEXPANDED | WASEXPANDEDTHISBLK): 
      (WASPERFORATED | WASPERFORATEDTHISBLK);
// dump_test_cert(done_certp, 1);
                                                  // step 2
    if (!diff_casn(&done_certp->origcertp->toBeSigned.issuer.self,
       &done_certp->origcertp->toBeSigned.subject.self)) break;
                                                        // step 3
    extp = find_extension(done_certp->origcertp, id_authKeyId, 0);
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
    if ((cc - skip) != 59 || *cc > ' ') return ERR_SCM_BADSKIBLOCK;
    *cc = 0;
    if ((ansr = get_CAcert(skip, &done_certp)) < 0) return ansr;
    ruleranges.numranges = 0;
    ruleranges.iprangep = (struct iprange *)0;
    if ((ansr = getSKIBlock(SKI)) < 0)
        return ansr; // with error message in skibuf BADSKIBLOCK
       // otherwise skibuf has another SKI line or NULL
    int err;

    err = process_control_block(done_certp);
    clear_ipranges(&ruleranges);
    if (err < 0) return err;
    }
  while(ansr);
  dump_test_certs(1);
  return 0;
  }

static char *next_cmd(char *buf, int siz, FILE *SKI)
  {
  char *c;
  do
    {
    if (!(c = fgets(skibuf, siz, SKI))) return c;
    }
  while(*skibuf == ';');
  return c;
  }
   
int read_SKI_blocks(scm *scmp, scmcon *conp, char *skiblockfile, FILE *logfile)
  {
/*
Procedure:
1. Open file for control data
   Get certificate for RP
   Get key information for RP
   Get any flags
   Get first SKI line from the control file
2. Process all the control blocks
   IF no error,
     FOR each item in done_certs
       Flag the target cert in the database as having a para
       Sign the paracertificate
       Put it into database with para flag
   Free all and return error
*/
  Certificate(&myrootcert, (ushort)0);
  char *c, *cc;
                                                     // step 1
  int ansr = 0;
  done_certs.numcerts = 0;
  FILE *SKI = fopen(skiblockfile, "r");

  if (!SKI) ansr = ERR_SCM_NOSKIFILE; // can't open
  else if (!next_cmd(skibuf, sizeof(skibuf), SKI) ||
    strncmp(skibuf, "PRIVATEKEYMETHOD", 16)) ansr = ERR_SCM_BADSKIFILE;
  else
    {
    for (cc = &skibuf[16]; *cc && *cc <= ' '; cc++);
    if (strncmp(cc, "Keyring", 7) ||
      check_keyring(cc) < 0) ansr = ERR_SCM_BADSKIFILE;
    }
  if (!ansr)
    {
    if (!next_cmd(skibuf, sizeof(skibuf), SKI) || 
      strncmp(skibuf, "TOPLEVELCERTIFICATE ", 20))
      ansr = ERR_SCM_NORPCERT;
    else
      {           // get root cert
      if ((c = strchr(skibuf, (int)'\n'))) *c = 0;
      if (get_casn_file(&myrootcert.self, &skibuf[20], 0) < 0)
        ansr = ERR_SCM_NORPCERT;
      else
        {
        for (c--; c > &skibuf[20] && *c != '/'; c--);
        if (*c != '/')
          {
          char *rootp = getenv("RPKI_ROOT");
          Xrpdir = (char *)calloc(1, strlen(rootp) + strlen(c) + 4);
          sprintf(Xrpdir, "%s/%s", rootp, c);
          }
        else 
          {
          *c = 0;
          Xrpdir = (char *)calloc(1, strlen(&skibuf[20]) + 4);
          strcpy(Xrpdir, &skibuf[20]);
          } 
        }
      }
    }
  if (!ansr && !next_cmd(skibuf, sizeof(skibuf), SKI)) 
    ansr = ERR_SCM_BADSKIFILE;
  else if (!ansr)   // CONTROL section
    {
    c = skibuf;
    while (c && !ansr && !strncmp(skibuf, "CONTROL ", 8))
      {
      if ((c = strchr(skibuf, (int)'\n'))) *c = 0;
      cc = nextword(skibuf);
      if (!strncmp(cc, "treegrowth", 10) && cc[10] == ' ' )
        {
        if (!strncmp(nextword(cc), "TRUE", 4) && nextword(cc)[4] <= ' ')
          locflags |= TREEGROWTH;
        }
      else if (!strncmp(cc, "resource_nounion", 16) && cc[16] == ' ')
        {
        if (!strncmp(nextword(cc), "TRUE", 4) && nextword(cc)[4]  <= ' ')
            locflags |= RESOURCE_NOUNION;
        }
      else if (!strncmp(cc, "intersection_always", 19) && cc[19] == ' ')
        {
        if (!strncmp(nextword(cc), "TRUE", 4) && nextword(cc)[4]  <= ' ')
            locflags |= INTERSECTION_ALWAYS;
        }
      else ansr = ERR_SCM_BADSKIFILE;
      if (!ansr) c = next_cmd(skibuf, sizeof(skibuf), SKI);
      }
    while (c && !ansr && !strncmp(skibuf, "TAG ", 4))
      {
      if ((c = strchr(skibuf, (int)'\n'))) *c = 0;
      cc = nextword(skibuf);
      if (!strncmp(cc, "Xvalidity_dates ", 16))
        {
        cc = nextword(cc);
        if (!*cc || (*cc != 'C'  && *cc != 'R' && check_dates(cc) < 0))
          ansr = ERR_SCM_BADSKIFILE;
        }
      else if (!strncmp(cc, "Xcrldp ", 7))
        {
        cc = nextword(cc);
        if (!*cc || (*cc == 'R' && cc[1] <= ' ' &&
          !find_extension(&myrootcert, id_cRLDistributionPoints, 0)))
          ansr = ERR_SCM_BADSKIFILE;
        else
          {
          Xcrldp = (char *)calloc(1, strlen(cc) + 2);
          strcpy(Xcrldp, cc);
          }
        }
      else if (!strncmp(cc, "Xcp ", 4))
        {
        struct Extension *extp;
        cc = nextword(cc);
        if (!*cc ||
          (*cc == 'R' &&
          ((!(extp = find_extension(&myrootcert, id_certificatePolicies, 0)))
          ||
          num_items(&extp->extnValue.certificatePolicies.self) > 1)))
          ansr = ERR_SCM_BADSKIFILE;
        else if (check_cp(cc) < 0) ansr = ERR_SCM_BADSKIFILE;
        }
      else if (!strncmp(cc, "Xaia ", 5))
        {
        cc = nextword(cc);
        Xaia = (char *)calloc(1, strlen(cc));
        strncpy(Xaia, cc, strlen(cc));
        }
      else ansr = ERR_SCM_BADSKIFILE;
      c = next_cmd(skibuf, sizeof(skibuf), SKI);
      }
    if (!Xcp) 
      {
      Xcp = (char *)calloc(1,4);
      *Xcp = 'D';
      }
    locscmp = scmp;
    locconp = conp;
    if (!c || strncmp(skibuf, "SKI ", 4)) ansr = ERR_SCM_BADSKIFILE;
    else ansr = process_control_blocks(SKI);
    }
  int numcert;
  struct done_cert *done_certp = done_certs.done_certp;
  int locansr = 0;
  char locfilename[128];
  *locfilename = 0;
  for (numcert = 0; numcert < done_certs.numcerts; numcert++, done_certp++)
    {
    if (ansr >= 0)
      {
      // mark done_certp->cert as having para
      done_certp->origflags |= SCM_FLAG_HASPARACERT;
      set_cert_flag(locconp, done_certp->origID, done_certp->origflags);
      // put done_certp->paracert in database with para flag
      if (locansr >= 0 && (locansr = add_paracert2DB(done_certp)) < 0)
        {
        if (logfile) fprintf(logfile, "%s ", done_certp->filename);
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
  free_keyring(&keyring);
  if (*skibuf && logfile) fprintf(logfile, "%s\n", skibuf);
  return ansr;
  }

