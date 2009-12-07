/*
  $Id: rpwork.h 888 2009-11-17 17:59:35Z gardiner $
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
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
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
#define WASEXPANDED       128
#define WASPERFORATED     256
#define SKIBUFSIZ         128

struct done_certs done_certs;

static int  locflags = 0;
static char skibuf[SKIBUFSIZ];
static char Xvalidity_dates[40];
static scm *locscmp;
static scmcon *locconp;
static struct Certificate myrootcert;
static struct ipranges certranges, ipranges;

static char *Xcrldp;

static char *Xcp;
 
static char *Xrpdir;
 
#include <fcntl.h>
static int ffindex;
 
static void dump_test_certs(struct done_cert *done_certp, int orig)
  {
  char locbuf[20];
  int fd, size;
  char *buf;
  if (orig)
    {
    size = dump_size(&done_certp->origcertp->self);
    buf = (char *)calloc(1, size + 2);
    size = dump_casn(&done_certp->origcertp->self, buf);
    sprintf(locbuf, "origcert%d.raw", ffindex);
    fd = open(locbuf, (O_CREAT | O_WRONLY | O_TRUNC), 0777);
    write(fd, buf, size);
    close(fd); 
    }
  size = dump_size(&done_certp->paracertp->self);
  buf = (char *)calloc(1, size + 2);
  size = dump_casn(&done_certp->paracertp->self, buf);
  sprintf(locbuf, "paracert%d.raw", ffindex++);
  fd = open(locbuf, (O_CREAT | O_WRONLY | O_TRUNC), 0777);
  write(fd, buf, size);
  close(fd); 
/*
  sprintf(locbuf, "paracert%d.cer", ffindex++);
  put_casn_file(&done_certp->paracertp->self, locbuf, 0);
*/
  }

static int add_paracert2DB(struct done_cert *done_certp)
  {
  int ansr;
  uint cert_id;
  char fullname[PATH_MAX];
  sprintf(fullname, "%s/%s", Xrpdir, done_certp->filename);
  ansr = add_cert(locscmp, locconp, done_certp->filename, fullname, 0, 0, 
    OT_CER, &cert_id);
  if (ansr >= 0) ansr = set_cert_flag(locconp, cert_id, 
    (ulong)(SCM_FLAG_ISPARACERT |  done_certp->origflags));   
  return ansr;
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
  for (i = 0; i < iprangesp->numranges; i++, iprangep++)
    {
    if (iprangep->text) free(iprangep->text);
    }
  free(iprangesp->iprangep);
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

static int cfrange(uchar *alim, uchar *blim, int lth)
  {
  struct iprange tiprange;
  memcpy(tiprange.lolim, blim, lth);
  memcpy(tiprange.hilim, alim, lth);
  increment_iprange(tiprange.hilim, lth);
  return memcmp(tiprange.hilim, tiprange.lolim, lth);
  }

static struct iprange *eject_range(struct ipranges *iprangesp, int num)
  {
  if (num < 0 || num > iprangesp->numranges) 
    internal_error("Ejecting out of range\n");  
  struct iprange *newrangep = (struct iprange *)calloc(
    iprangesp->numranges - 1, sizeof(struct iprange));
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
  iprangesp->numranges++;
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
 
static int getAKI(char *namep, struct casn *idp)
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
    else 
      {
      clear_casn(&textp->extnValue.self);
      write_objid(&textp->extnID, id_certificatePolicies);
      struct PolicyInformation *polInfop = (struct PolicyInformation *)
        inject_casn(&textp->extnValue.certificatePolicies.self, 0);
      if (*Xcp == 'D') write_objid(&polInfop->policyIdentifier, id_anyPolicy);
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
  int i;
  struct done_cert *done_certp;

  if (ski && (done_certp = have_already(ski)))
    {
    done_certp = &done_certs.done_certp[i];
    *done_certpp = done_certp;
    i = 0;
    }
  else   //  no, get it from DB as certp
    {
    int ansr; 
    struct cert_answers *cert_answersp = 
      find_cert_by_aKI(ski, (char *)0, locscmp, locconp); 
    if (!cert_answersp) return -1;
    struct cert_ansr *cert_ansrp;
    ansr = cert_answersp->num_ansrs; 
    char filename[PATH_MAX];
    if (ansr < 0) return ansr;
    if (ansr == 1)
      {
      cert_ansrp = &cert_answersp->cert_ansrp[0];
      certp = (struct Certificate *)calloc(1, sizeof(struct Certificate));
      Certificate(certp, (ushort)0);
      if ((ansr = get_casn_file(&certp->self, cert_ansrp->fullname, 0)) < 0)
        return ERR_SCM_COFILE;
      strcpy(filename, cert_ansrp->filename);
      }
         // if DB returns two certs or other error, return error
    struct Certificate *paracertp = mk_paracert(certp);
    if (!paracertp) ansr = ERR_SCM_BADSKIFILE;
    else if ((ansr = add_done_cert(ski, certp, paracertp, cert_ansrp->flags, 
      cert_ansrp->local_id, cert_ansrp->filename)) >= 0) 
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
    inject_range(&ipranges, ipranges.numranges);
    struct iprange *iprangep = &ipranges.iprangep[ipranges.numranges - 1];
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
  else if (ipranges.numranges == 0)
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
3. ELSE make a range and write it
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
    {  // low end
    strlth = ((numbits + 8) >> 3); // index to 1st diff
    memcpy(&bitstring[1], tiprangep->lolim, strlth);
    bitstring[0] = 0;
    write_casn(&ipAddrOrRangep->addressRange.min, bitstring, strlth + 1); 

      // high end  
    memcpy(&bitstring[1], tiprangep->hilim, strlth);
    bitstring[0] = 0;
    write_casn(&ipAddrOrRangep->addressRange.max, bitstring, strlth + 1);   
    } 
  }

static int expand(int numrange, int numcertrange, int *changesp)
  {
/*
Function: Expands certificate fields to match a constraint
Inputs: typ
        
   Starting at first constraint (one guaranteed and first cert field of this 
     type (not guaranteed) 
   FOR each constraint of this type
1.   IF there is no cert field of this type
       Make one with the limits of the constraint
       Get non-existent certrange
       Continue in FOR
2.   Process constr lolim:
     WHILE cert hilim < constr lolim
       IF there's a next cert, get it as current one
       ELSE make a new certrange with constr limits
3.   Process constr hilim:
     WHILE cert hilim < constr hilim
       IF no next cert
         Set cert hilim to constr hilim
       ELSE WHILE have a next cert AND nextcert lolim <= constr hilim
         Set cert hilim to next cert hilim
         Delete nextcert
*/
  int did = 0;
  struct iprange *certrangep = &certranges.iprangep[numcertrange], 
    *constrangep = &ipranges.iprangep[numrange];
  int typ = constrangep->typ;
  int lth = (constrangep->typ == IPv6)? 16: 4;
  for ( ; constrangep; 
    constrangep = next_range(&ipranges, constrangep), numrange++)
    {                                          // step 1
    if (certrangep->typ != typ) 
      {
      certrangep = inject_range(&certranges, numcertrange);
      certrangep->typ = typ;
      memcpy(certrangep->lolim, constrangep->lolim, lth);
      memcpy(certrangep->hilim, constrangep->hilim, lth);
      did++;
      continue;
      }
                                              // step 2
    while (cfrange(certrangep->hilim, constrangep->lolim, lth) < 0)
      {
      if (certrangep[1].typ == typ)
        {
        certrangep++;
        numcertrange++;
        }
      else 
        {
        certrangep = inject_range(&certranges, ++numcertrange);
        certrangep->typ = typ;
        memcpy(certrangep->lolim, constrangep->lolim, lth);
        memcpy(certrangep->hilim, constrangep->hilim, lth);
        }
      }
                                                    // step 3  
    while(cfrange(certrangep->hilim, constrangep->hilim, lth) < 0)
      {
      if (certrangep[1].typ != typ)
        memcpy(certrangep->hilim, constrangep->hilim, lth);
      else while (certrangep[1].typ == typ && 
        cfrange(certrangep[1].lolim, constrangep->hilim, lth) >= 0) 
        {
        memcpy(certrangep->hilim, certrangep[1].hilim, lth);
        certrangep = eject_range(&certranges, numcertrange);
        certrangep--;
        }  
      }
    }
  return numrange;
  }

static int perforate(int numrange, int numcertrange, int *changesp)
  {
/*
Procedure:
   Starting at first constraint (one guaranteed and first cert field of this 
     type (not guaranteed) 
1. FOR each constraint
     WHILE cert hilim < constraint lolim
       Go to next item in cert, if any
2.   WHILE have a cert entry AND its lolim < constraint's hilim
       IF certrange is within SKI range, delete certrange
3.     ELSE IF certrange extends before SKI range on low end
         IF certrange extends beyond SKI range on high end, too
           Cut the present cert item to stop just before SKI item
           Add a new cert item just beyond the SKI item
4.       ELSE Cut the high end of the cert item back to just before 
           the SKI item
5.     ELSE IF certrange goes beyond the SKI range
         Cut the start of the cert item forward to just beyond the SKI item
       Go to next cert entry
*/
  struct iprange *certrangep = &certranges.iprangep[numcertrange], 
    *constrangep = &ipranges.iprangep[numrange];
  int did = 0, typ = certrangep->typ, lth = (typ == IPv6)? 16: 4;       
                                                  // step 1
  for ( ; constrangep; 
    constrangep = next_range(&ipranges, constrangep), numrange++)
    {                                              // step 2
    while(certrangep && 
      memcmp(certrangep->hilim, constrangep->lolim, lth) < 0)
      {
      certrangep = next_range(&certranges, certrangep);
      numcertrange++;
      }
                                                   // step 2
    while(certrangep && 
      memcmp(certrangep->lolim, constrangep->hilim, lth) < 0)
      {
      if (memcmp(certrangep->lolim, constrangep->lolim, lth) >= 0 &&
        memcmp(certrangep->hilim, constrangep->hilim, lth) <= 0)
        {
        certrangep = eject_range(&certranges, numcertrange);
        }
                                                       // step 3
      else if(memcmp(certrangep->lolim, constrangep->lolim, lth) < 0) 
        {
        if (memcmp(certrangep->hilim, constrangep->hilim, lth) > 0)
          {
          certrangep = inject_range(&certranges, ++numcertrange);
          certrangep->typ = typ;
          memcpy(certrangep->hilim, certrangep[-1].hilim, lth);
          memcpy(certrangep[-1].hilim, constrangep->lolim, lth);
          decrement_iprange(certrangep[-1].hilim, lth);
          memcpy(certrangep->lolim, constrangep->hilim, lth);
          increment_iprange(certrangep->lolim, lth);
          }
                                                            // step 4
        else 
          {
          memcpy(certrangep->hilim, constrangep->lolim, lth);
          decrement_iprange(certrangep->hilim, lth);
          }
        }
                                                         // step 5
      else if (memcmp(certrangep->hilim, constrangep->hilim, lth) > 0)
        {
        memcpy(certrangep->lolim, constrangep->hilim, lth);
        increment_iprange(certrangep->lolim, lth);
        }
      }
    }
  *changesp += did;
  return numrange;
  }

static int run_through_typlist(int run, int numrange, int numcertrange, 
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
   Reconstruct IP addresses in cert from ipranges
   Note ending point in list
*/
  int did;
                                                  // step 1
  if (!run) did = expand(numrange, numcertrange, changesp);
  else did = perforate(numrange, numcertrange, changesp);
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
4. IF cert has any AS# extensions, empty them
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
  if (ansr) ansr = ERR_SCM_SIGNINGERR;
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
1. Enlarge or perforate para-certificate's IPv4 addresses 
2. Enlarge or perforate para-certificate's IPv6 addresses 
3. Enlarge or perforate para-certificate's AS numbers
   Return count of changes made. if any
*/
  int numrange = 0, numcertrange, typ, changes = 0;
    // start at beginning of SKI list and IPv4 family in certificate
  struct iprange *tiprangep = ipranges.iprangep;   // beginning of SKI list
                                                 // step 1
  typ = IPv4;  
  numcertrange = 0;
  if (tiprangep->typ == typ &&
    (numrange = run_through_typlist(run, numrange, numcertrange, 
    &changes)) < 0) return numrange;
  tiprangep = &ipranges.iprangep[numrange];
                                 // step 2
  typ = IPv6; 
  struct iprange *certrangep;
  for (certrangep = &certranges.iprangep[numcertrange];
      certrangep->typ && certrangep->typ < typ; certrangep++);    
  numcertrange = (certrangep - certranges.iprangep); 
  if (tiprangep->typ == typ &&
    (numrange = run_through_typlist(run, numrange, numcertrange,
      &changes)) < 0) return numrange;
  tiprangep = &ipranges.iprangep[numrange];
                                   // step 3
  typ = ASNUM;  
  for (certrangep = &certranges.iprangep[numcertrange];
      certrangep->typ && certrangep->typ < typ; certrangep++);    
  numcertrange = (certrangep - certranges.iprangep); 
  if (tiprangep->typ == typ  &&
    (numrange = run_through_typlist(run, numrange, numcertrange, 
      &changes)) < 0) return numrange;
  remake_cert_ranges(paracertp);
  sign_cert(paracertp);
  return changes;
  }

static int search_downward(struct Certificate *topcertp)
  {
/*
Function: Looks for any instances of ipranges in the children of the cert  
  and perforates them
Inputs: starting certificate
        list or ranges 
        number of ranges
Procedure:
1. FOR each of its children
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
  getAKI(skibuf, &extp->extnValue.subjectKeyIdentifier);
  
  // Get list of children having skibuf as their AKI
  struct cert_answers *cert_answersp = 
    find_cert_by_aKI((char *)0, skibuf, locscmp, locconp); 
  numkids = cert_answersp->num_ansrs;
  childcertp = (struct Certificate *)calloc(1, sizeof(struct Certificate));
  Certificate(childcertp, (ushort)0);

  for (ansr = numkid = 0; numkid < numkids && ansr >= 0; numkid++)
    {
    struct cert_ansr *cert_ansrp = &cert_answersp->cert_ansrp[numkid];
    if ((ansr = get_casn_file(&childcertp->self, cert_ansrp->fullname, 0)) < 0)
        return ERR_SCM_COFILE;
    extp = find_extension(childcertp, id_subjectKeyIdentifier, 0);
    getAKI(skibuf, &extp->extnValue.subjectKeyIdentifier);
    struct done_cert *done_certp, done_cert;
    int have = 0;
    if (!(done_certp = have_already(skibuf))) 
      {
      done_certp = &done_cert;
      strcpy(done_cert.ski, skibuf);
      done_cert.origcertp = (struct Certificate *)
      calloc(1, sizeof(struct Certificate));
      Certificate(done_cert.origcertp, (ushort)0);  
      copy_casn(&done_cert.origcertp->self, &childcertp->self);
      done_cert.origID = cert_ansrp->local_id;
      done_cert.paracertp =  mk_paracert(childcertp);
dump_test_certs(&done_cert, 1);
      }
    else have = 1;
                                                // step 2
    ansr = modify_paracert(1, done_certp->paracertp);
    if (have == 0)   // it is a temporary done_cert
      {
      if (ansr <= 0)
        {
        delete_casn(&done_certp->origcertp->self);
        delete_casn(&done_certp->paracertp->self);
        }
      else add_done_cert(done_cert.ski, done_cert.origcertp, 
        done_cert.paracertp, done_cert.origID, done_cert.origflags, 
        done_cert.filename);
      }
    if (ansr > 0) ansr = search_downward(done_certp->origcertp);
    }
  return ansr;
  }

static int process_control_block(struct done_cert *done_certp)
  {
/*
Function: processes an SKI block, including ancestors
Inputs: ptr to ski entries
        ptr to base cert
Returns: 0 if OK else error code
Procedure:
1. FOR each run until a self-signed
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
    done_certp->perf |= (!run)? WASEXPANDED: WASPERFORATED;
dump_test_certs(done_certp, 1);
                                                  // step 2
    if (!diff_casn(&done_certp->origcertp->toBeSigned.issuer.self, 
       &done_certp->origcertp->toBeSigned.subject.self)) break;
                                                        // step 3     
    extp = find_extension(done_certp->origcertp, id_authKeyId, 0);
    getAKI(skibuf, &extp->extnValue.authKeyId.keyIdentifier);
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
    ipranges.numranges = 0;
    ipranges.iprangep = (struct iprange *)0;
    if ((ansr = getSKIBlock(SKI)) < 0) 
        return ansr; // with error message in skibuf BADSKIBLOCK
       // otherwise skibuf has another SKI line or NULL
    int err;
    
    err = process_control_block(done_certp);
    clear_ipranges(&ipranges);
    if (err < 0) return err;
    }
  while(ansr);
  return 0;
  } 

int read_SKI_blocks(scm *scmp, scmcon *conp, char *skiblockfile, 
  FILE *logfile, FILE *s)
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
  else if (!fgets(skibuf, sizeof(skibuf), SKI) || 
    strncmp(skibuf, "PRIVATEKEYMETHOD", 16))
    ansr = ERR_SCM_BADSKIFILE;
  else
    {
    for (cc = &skibuf[16]; *cc && *cc <= ' '; cc++);
    if (strncmp(cc, "Keyring", 7) ||
      check_keyring(cc) < 0) ansr = ERR_SCM_BADSKIFILE;
    }      
  if ((!ansr && 
    !fgets(skibuf, sizeof(skibuf), SKI)) || strncmp(skibuf, "RP ", 3)) 
    ansr = ERR_SCM_NORPCERT;  
  else
    {           // get root cert
    if ((c = strchr(skibuf, (int)'\n'))) *c = 0;
    if (get_casn_file(&myrootcert.self, &skibuf[3], 0) < 0) 
      ansr = ERR_SCM_NORPCERT;  
    }
  if (!ansr && !fgets(skibuf, sizeof(skibuf), SKI)) ansr = ERR_SCM_BADSKIFILE;
  else
    {
    if ((c = strchr(skibuf, (int)'\n'))) *c = 0;
    if (!strncmp(skibuf, "RPDIR ", 6))
      {
      if (!(cc = nextword(skibuf))) ansr = ERR_SCM_BADSKIFILE;
      else 
        {
        char *rootp = getenv("APKI_ROOT");
        Xrpdir = (char *)calloc(1, strlen(rootp) + strlen(cc) + 4);
        sprintf(Xrpdir, "%s/%s", rootp, cc);
        }
      }
    if (!ansr && !fgets(skibuf,sizeof(skibuf), SKI)) ansr = ERR_SCM_BADSKIFILE;
    else
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
        if (!ansr) c = fgets(skibuf, sizeof(skibuf), SKI);
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
        c = fgets(skibuf, sizeof(skibuf), SKI);
        }   
      locscmp = scmp;
      locconp = conp;
      if (!c || strncmp(skibuf, "SKI ", 4)) ansr = ERR_SCM_BADSKIFILE; 
      else ansr = process_control_blocks(SKI);
      }
    }
  int numcert;
  struct done_cert *done_certp = done_certs.done_certp;
  int locansr = 0;
  char locfilename[128];
  *locfilename = 0;
  for (numcert = 0; numcert < done_certs.numcerts; numcert++, done_certp++)
    {
    // mark done_certp->SKI cert as having para
    done_certp->origflags |= SCM_FLAG_HASPARACERT;
    set_cert_flag(locconp, done_certp->origID, done_certp->origflags); 
    // put done_certp->paracert in database with para flag
    if (locansr >= 0 && (locansr = add_paracert2DB(done_certp)) < 0) 
      {
      fprintf(s, "%s ", done_certp->filename);
      if (logfile) fprintf(logfile, "%s ", done_certp->filename);
      strcpy(locfilename, done_certp->filename);
      *skibuf = 0;
      }
    delete_casn(&done_certp->origcertp->self);
    delete_casn(&done_certp->paracertp->self);
    free(done_certp->origcertp);
    free(done_certp->paracertp);
    }
  if (!ansr) ansr = locansr;
  fclose(SKI);
  delete_casn(&myrootcert.self);
  if (Xcp) free(Xcp);
  if (Xaia) free(Xaia);
  free(Xcrldp);
  free_keyring(&keyring);
  if (*skibuf) 
    {
    fprintf(s, "%s\n", skibuf);
    if (logfile) fprintf(logfile, "%s\n", skibuf);
    }
  return ansr;
  }

