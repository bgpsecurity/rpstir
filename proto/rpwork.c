#include <string.h>
#include <stdio.h>
#include "conversion.h"

#define INTERSECTION_ALWAYS 1
#define RESOURCE_NOUNION    2
#define PARACERT            4
#define WASEXPANDED         8
#define WASPERFORATED      16
#define SKIBUFSIZ 128

struct done_cert
  {
  char ski[42];
  int perf;   // 0= expanded, 1= perforated
  struct Certificate *origcertp, *paracertp;
  };

struct done_certs
  {
  int numcerts;
  struct done_cert *done_certp;
  } done_certs;

struct ipranges
  {
  int numranges;
  struct iprange *iprangep;
  };

struct certificates 
  {
  int numcerts;
  struct Certificate *certificatesp;
  };

static int  locflags = 0;

static struct Certificate myrootcert;

static int add_done_cert(char *skip, struct Certificate *certp, 
  struct Certificate *paracertp)
  {
  if (!done_certs.numcerts) done_certs.done_certp = (struct done_cert *)
      calloc(1, sizeof(struct done_cert));
  else done_certs.done_certp = (struct done_cert *)
      realloc(done_certs.done_certp, 
      (sizeof(struct done_cert) * (++done_certs.numcerts)));
  struct done_cert *done_certp = &done_certs.done_certp[done_certs.numcerts]; 
  strcpy(done_certp->ski, skip);
  done_certp->origcertp = certp;
  done_certp->paracertp = paracertp;
  return done_certs.numcerts - 1;
  }

static void add_iprange(struct ipranges *iprangesp)
  {
  if (iprangesp->numranges == 0) 
    iprangesp->iprangep = (struct iprange *) calloc(1,  sizeof(struct iprange));
  else 
    {
    iprangesp->iprangep = (struct iprange *)realloc(iprangesp->iprangep, 
        (sizeof(struct iprange) * (iprangesp->numranges + 1)));
    iprangesp->iprangep[iprangesp->numranges].typ = 0;
    }
  iprangesp->numranges++;
  }

static struct Extension *find_extension(struct Extensions *extsp, char *oid, 
  int add)
  {
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

static int getAKI(char *namep, struct casn *idp)
  {
  int lth = size_casn(idp);
  uchar *uc, casnbuf[64];
  read_casn(idp, casnbuf);
  char *c;
  for (uc = casnbuf, c = namep; uc < &casnbuf[lth]; c += 2)
    {
    int i;
    i = *uc++;
    i <<= 4;
    i |= *uc++;
    sprintf(c, "%02x", i);
    }
  return (c - namep);
  }

static struct done_cert *have_already(char *ski)
  {
  int i;    
  for (i = 0; 
    i < done_certs.numcerts && !strcmp(done_certs.done_certp[i].ski, ski);
     i++);
  if (i < done_certs.numcerts) return &done_certs.done_certp[i];
  return (struct done_cert *)0;
  }

static struct Certificate *mk_paracert(struct Certificate *origcertp)
  {
  struct Certificate *newcertp = (struct Certificate *)calloc(1,
    sizeof(struct Certificate));
  Certificate(newcertp, (ushort)0);
  copy_casn(&newcertp->self, &origcertp->self);
  copy_casn(&newcertp->toBeSigned.issuer.self, 
    &origcertp->toBeSigned.subject.self);
  struct Extension *skiExtp, *akiExtp;
  if (!(skiExtp = find_extension(&myrootcert.toBeSigned.extensions,
    id_subjectKeyIdentifier, 0)))
    {
    // print message?
    return (struct Certificate *)0;
    }
  if (!(akiExtp = find_extension(&newcertp->toBeSigned.extensions,
    id_authKeyId, 1)))
    {
    // print message?
    return (struct Certificate *)0;
    }
  copy_casn(&akiExtp->self, &skiExtp->self);
  return newcertp;
  }

static int get_CAcert(char *ski, struct done_cert **done_certpp)
  {  // use INTERSECTION_ALWAYS
  struct Certificate *certp = (struct Certificate *)0;
  int i;
  struct done_cert *done_certp;

  if ((done_certp = have_already(ski)))
    {
    done_certp = &done_certs.done_certp[i];
    *done_certpp = done_certp;
    i = 0;
    }
  else   //  no, get it from DB as certp
    {  
         // if DB returns two certs or other error, return error
    struct Certificate *paracertp = mk_paracert(certp);
    int ansr;
    if ((ansr = add_done_cert(ski, certp, paracertp)) < 0) return ansr;
    if (!done_certp->paracertp) return -1; // error making paracert
    i = 1;
    }
  return i;
  }

static struct AddressesOrRangesInIPAddressChoiceA *find_IP(int typ, 
    struct Extension *extp)
  { 
  uchar fambuf[4];
  int loctyp;
  if (typ == IPV4) loctyp = 1;
  else if (typ == IPV6) loctyp = 2;
  else return (struct AddressesOrRangesInIPAddressChoiceA *)0;
  struct IpAddrBlock *ipAddrBlock = &extp->extnValue.ipAddressBlock;
  struct IPAddressFamilyA *ipFamp;
  for (ipFamp = (struct IPAddressFamilyA *)member_casn(
        &ipAddrBlock->self, 0);  1; 
    ipFamp = (struct IPAddressFamilyA *)next_of(&ipAddrBlock->self))
    {
    read_casn(&ipFamp->addressFamily, fambuf);
    if (fambuf[1] == loctyp)  // OK the cert has some
     return &ipFamp->ipAddressChoice.addressesOrRanges;
    }  
  return (struct AddressesOrRangesInIPAddressChoiceA *)0;
  }

static int getIPBlock(FILE *SKI, char *skibuf, struct ipranges *iprangesp, 
  int typ)
  {
  char *c;
  while((c = fgets(skibuf, sizeof(skibuf), SKI)))
    {
    if ((typ == IPV4 && *skibuf == 'I') || (typ == IPV6 && *skibuf == 'A') ||
      (typ < 0 && *skibuf == 'S')) break;
    add_iprange(iprangesp);
    }
  struct iprange *iprangep = &iprangesp->iprangep[iprangesp->numranges - 1];
  if (txt2loc(typ, skibuf, iprangep) < 0) return -1;
  if (!c) *skibuf = 0;
  return (c)? 1: 0;
  }
 
static int getSKIBlock(FILE *SKI, char *skibuf, struct ipranges *iprangesp)
  {
  int ansr;
  if (!fgets(skibuf, sizeof(skibuf), SKI) || strcmp(skibuf, "IPv4\n"))
    {
    strcpy(skibuf, "Missing IPv4");
    return -1;
    }
  if (getIPBlock(SKI, skibuf, iprangesp, IPV4) < 0);
    {
    strcpy(skibuf, "Bad IPv4 group");
    return -1;
    }
  if (strcmp(skibuf, "IPv6\n"))
    {
    strcpy(skibuf, "Missing IPv6");
    return -1;
    }
  if (getIPBlock(SKI, skibuf, iprangesp, IPV6) < 0);
    {
    strcpy(skibuf, "Bad IPv6 group");
    return -1;
    }
  if (strcmp(skibuf, "AS#"))
    {
    strcpy(skibuf, "Missing AS#");
    return -1;
    }
  if((ansr = getIPBlock(SKI, skibuf, iprangesp, ASNUM)) < 0)
    strcpy(skibuf, "Bad AS# group");
  else if (iprangesp->numranges == 0)
  return ansr;
  }
  
static int make_ASnum(struct ASNumberOrRangeA *asNumberOrRangep,
  struct iprange *iprangep)
  {
  if (iprangep->loASnum == iprangep->hiASnum)
    write_casn_num(&asNumberOrRangep->num, iprangep->loASnum);
  else
    {
    write_casn_num(&asNumberOrRangep->range.min, iprangep->loASnum);
    write_casn_num(&asNumberOrRangep->range.max, iprangep->hiASnum);
    }
  return 1;
  }

static int make_IPAddrOrRange(struct IPAddressOrRangeA *ipAddrOrRangep, 
  struct iprange *tiprangep)
  {
/*
Procedure:
1. Running from left to right, find where the low and high of tiprangep differ
   Count the number of bits where they match
2. IF beyond that point lolim is all zeroes and hilim all ones, write a prefix
3. ELSE make a range and write it
*/
  int lth = tiprangep->typ == IPV4? 4: 16;
  uchar *hucp, *lucp, mask, *eucp = &tiprangep->lolim[lth];
  int lonumbits, hinumbits, numbits = 0;
                                                   // step 1
  for (lucp = tiprangep->lolim, hucp = tiprangep->hilim; 
    lucp < eucp && *lucp == *hucp;
    lucp++,  hucp++, numbits += 8);
  if (lucp < eucp) 
    {
    for (mask = 0x80; mask && (mask & *lucp) == (mask & *hucp); 
      mask >>= 1, lucp++, hucp++, numbits++);
    }
  lonumbits = hinumbits = lth << 3;
  for (lucp = &eucp[-1]; lucp > tiprangep->lolim && !*lucp; 
    lucp--, lonumbits -= 8);
  if (lucp >= tiprangep->lolim)
    {
    for(mask = 1; mask && !(mask & *lucp); mask <<= 1, lonumbits--);
    }
  for(hucp = &tiprangep->hilim[lth - 1]; 
    hucp > tiprangep->hilim && *lucp == 0xff; hucp--, hinumbits -= 8);
  if (hucp > tiprangep->hilim)
    {
    for (mask = 1; mask && (mask & *hucp); mask <<= 1, hinumbits--);
    }        
                                                 // step 2
  uchar bitstring[18];
  int strlth;
  if (lonumbits == hinumbits && numbits == hinumbits - 1)
    {
    strlth = (numbits + 7) >> 3;
    memcpy(&bitstring[1], tiprangep->lolim, strlth);
    bitstring[0] = (8 - (numbits & 7)) & 7;
    write_casn(&ipAddrOrRangep->addressPrefix, bitstring, strlth + 1);
    }
                                                   // step 3
  else  
    {  // low end
    strlth = lth - ((lonumbits + 7) >> 3);
    memcpy(&bitstring[1], tiprangep->lolim, strlth);
    bitstring[0] = lonumbits & 7;
    write_casn(&ipAddrOrRangep->addressRange.min, bitstring, strlth + 1); 

      // high end  
    strlth = lth - ((hinumbits + 7) >> 3);
    memcpy(&bitstring[1], tiprangep->hilim, strlth);
    bitstring[0] = hinumbits & 7;
    write_casn(&ipAddrOrRangep->addressRange.max, bitstring, strlth + 1);   
    } 
  return 1;
  }
  
static int expand_cert(struct iprange *constrangep,  
  struct AddressesOrRangesInIPAddressChoiceA *ipAddrOrRangesp, int *changesp)
  {
/*
Function: Expands certificate fields to match a constraint
Inputs: typ
        
1, Starting at first constraint, FOR all constraints of this type
     WHILE have a cert item AND its hilim < constr lolim  go to next cert item
2.   IF have no cert item OR constr hilim < cert lolim  (case a)
       Make a new cert item for the entire constraint
3.   ELSE IF constr lolim <= cert cert hilim   
       IF there is no nextcert OR constr hilim < nextcert lolim  (case b)
         Extend cert hilim to constr hilim
       ELSE                                   (case c)
         WHILE constr hilim >= nextcert lolim
           Delete current cert item
           Extend nextcert lolim to constr lolim
4.   ELSE IF constr lolim > cert lolim AND constr hilim > cert hilim
       Do nothing   )case d)
5.   ELSE IF constr hilim >= nextcert lolim  (case e)
       Extend cert lolim to constraint lolim
     Go to next constraint
*/
  int num_cert_item = 0, num_cert_items = num_items(&ipAddrOrRangesp->self),
    did = 0, lth = (constrangep->typ == IPV4)? 4: 16;
  struct IPAddressOrRangeA *ipAddrOrRangep = (struct IPAddressOrRangeA *)
    member_casn(&ipAddrOrRangesp->self, num_cert_item);
  struct iprange certrange, nextcertrange;
  cvt_asn(&certrange, ipAddrOrRangep); 
  int typ;
  for (typ = constrangep->typ; constrangep->typ == typ; constrangep++)
    {
    while(num_cert_item < num_cert_items && 
      memcmp(certrange.hilim, constrangep->lolim, lth) < 0)
      {
      ipAddrOrRangep = (struct IPAddressOrRangeA *)
        member_casn(&ipAddrOrRangesp->self, ++num_cert_item);
      cvt_asn(&certrange, ipAddrOrRangep);
      }
    if (num_cert_item == num_cert_items ||             // step 2
      memcmp(constrangep->hilim, certrange.lolim, lth) < 0) // case a
      {
      ipAddrOrRangep  = (struct IPAddressOrRangeA *)inject_casn(
        &ipAddrOrRangesp->self, num_cert_item);
      num_cert_items++;
      num_cert_item++;
      did += make_IPAddrOrRange(ipAddrOrRangep, constrangep);
      }                                                         // step 3
    else if (memcmp(constrangep->lolim, certrange.hilim, lth) <= 0) 
      {
      struct IPAddressOrRangeA *nipAddrOrRangep = 
        (struct IPAddressOrRangeA *)0;
      if (num_cert_item + 1 < num_cert_items) nipAddrOrRangep  = 
        (struct IPAddressOrRangeA *)
        member_casn(&ipAddrOrRangesp->self, (num_cert_item + 1));
        cvt_asn(&nextcertrange, nipAddrOrRangep);
      if (!nipAddrOrRangep || 
        memcmp(constrangep->hilim, nextcertrange.lolim, lth) < 0) //case b
        {
        memcpy(certrange.hilim, constrangep->hilim, lth);
        did += make_IPAddrOrRange(ipAddrOrRangep, &certrange);
        }
      else 
        {      // must have a nipAddrOrRangep at start
        do                                      // case c
          {
          eject_casn(&ipAddrOrRangesp->self, num_cert_item);
          num_cert_items--;
          ipAddrOrRangep = nipAddrOrRangep;
          memcpy(&certrange, &nextcertrange, sizeof(struct iprange));
          memcpy(certrange.lolim, constrangep->lolim, lth);
          if (num_cert_item + 1 < num_cert_items)
            {
            nipAddrOrRangep = (struct IPAddressOrRangeA *)member_casn(
              &ipAddrOrRangesp->self, (num_cert_item + 1));
            cvt_asn(&nextcertrange, nipAddrOrRangep);
            }
          else if(memcmp(constrangep->hilim, certrange.lolim, lth) >= 0)
            {
            nipAddrOrRangep = (struct IPAddressOrRangeA *)inject_casn(
              &ipAddrOrRangesp->self, ++num_cert_item);
            num_cert_items++;
            cvt_asn(&nextcertrange, nipAddrOrRangep);
            }
          }
        while(memcmp(constrangep->hilim, certrange.lolim, lth) >= 0);
        did += make_IPAddrOrRange(ipAddrOrRangep, &certrange);
        }
      }                                              // step 4
    else if (memcmp(certrange.lolim, constrangep->lolim, lth) < 0 &&
      memcmp(certrange.hilim, constrangep->hilim, lth) > 0) {} // case d
    else if (memcmp(constrangep->hilim, certrange.lolim, lth) >= 0)
      {                                                  // step 5
      memcpy(certrange.lolim, constrangep->lolim, lth);   // case e
      did += make_IPAddrOrRange(ipAddrOrRangep, &certrange);
      }
    }
  return did;
  }

static int perforate_cert(
  struct AddressesOrRangesInIPAddressChoiceA *ipAddrOrRangesp, 
  int num_addr, struct iprange *certrangep, struct iprange *skirangep,
  int *changesp)
  {
/*
Procedure:
1. IF certrange is within SKI range, delete certrange
2. ELSE IF certrange extends beyond SKI range on both ends
    Cut the present cert item to stop just before SKI item
    Add a new cert item just beyond the SKI item
3. ELSE IF certrange starts before SKI range
     Cut the high end of the cert item back to just before the SKI item
4. ELSE IF certrange goes beyond the SKI range
     Cut the start of the cert item forward to just beyond the SKI item
*/
  int did = 0, lth = skirangep->typ == IPV4? 4: 16;            
  struct iprange tiprange;
  struct IPAddressOrRangeA *ipAddrOrRangep = (struct IPAddressOrRangeA *)
    member_casn(&ipAddrOrRangesp->self, num_addr);
  tiprange.typ = skirangep->typ;             
                                                  // step 1
  if (memcmp(certrangep->lolim, skirangep->lolim, lth) >= 0 &&
    memcmp(certrangep->hilim, skirangep->hilim, lth) <= 0)
    eject_casn(&ipAddrOrRangesp->self, num_addr--);
                                                   // step 2
  else if(memcmp(certrangep->lolim, skirangep->lolim, lth) < 0 &&
    memcmp(certrangep->hilim, skirangep->hilim, lth) > 0)
    {
    memcpy(tiprange.lolim, certrangep->lolim, lth);
    memcpy(tiprange.hilim, skirangep->hilim, lth);
    decrement_iprange(tiprange.hilim, lth);
    did += make_IPAddrOrRange(ipAddrOrRangep, &tiprange);
    memcpy(tiprange.lolim, skirangep->hilim, lth);
    increment_iprange(tiprange.lolim, lth);
    memcpy(tiprange.hilim, certrangep->hilim, lth);;
    ipAddrOrRangep = (struct IPAddressOrRangeA *)inject_casn(
      &ipAddrOrRangesp->self, ++num_addr);
    did += make_IPAddrOrRange(ipAddrOrRangep, &tiprange);
    }
                                                      // step 3
  else if (memcmp(certrangep->lolim, skirangep->lolim, lth) < 0)
    {
    memcpy(tiprange.lolim, certrangep->lolim, lth);
    memcpy(tiprange.hilim, skirangep->lolim, lth);
    decrement_iprange(tiprange.hilim, lth);
    did += make_IPAddrOrRange(ipAddrOrRangep, &tiprange);
    }
                                                     // step 4
  else if (memcmp(certrangep->hilim, skirangep->hilim, lth) > 0)
    {
    memcpy(tiprange.lolim, skirangep->hilim, lth);
    increment_iprange(tiprange.lolim, lth);
    memcpy(tiprange.hilim, certrangep->hilim, lth);
    did += make_IPAddrOrRange(ipAddrOrRangep, &tiprange);
    }
  *changesp += did;
  return num_addr;
  }

static int perforate_ASNum(struct AsNumbersOrRangesInASIdentifierChoiceA 
  *asNumbersOrRangesp,
  int num_addr, struct iprange *certrangep, struct iprange *skirangep,
  int *changesp)
  {
  return 0;
  }
                     
static int run_through_ASlist(int run, struct ipranges *iprangesp, 
  int numrange, 
  struct AsNumbersOrRangesInASIdentifierChoiceA *asNumbersOrRangesp,
  int *changesp) 
  {
/*
Procedure:
1. Convert cert's starting number(s)
   DO
2.   IF expanding
       WHILE cert hiASnum < constr loASnum  go to next cert item
       IF constr hiASnum < cert loASnum  (case a)
         Make a new cert item for the entire constraint
       ELSE IF constr loASnum <= cert cert hiASnum   
         IF constr hiASnum < nextcert loASnum  (case b)
           Extend cert hiASnum to constr hiASnum
         ELSE DO         (case c)
           Delete current cert item
           Extend nextcert loASnum to constr loASnum
           WHILE constr hiASnum >= nextcert loASnum
       ELSE IF constr loASnum > cert loASnum AND constr hiASnum > cert hiASnum
         Do nothing   )case d)
       ELSE IF constr hiASnum >= nextcert loASnum  (case e)
         Extend cert loASnum to constraint loASnum
     ELSE
       WHILE cert hilim < constr lolim
         Go to next item in cert
3.     WHILE have a cert item AND Its cert lolim < constr hilim
         Perforate cert, noting need to flag old cert
         Go to bext item in cert
     Get next constr entry 
   WHILE lis entry is of current type
*/
  int did = 0, num_addr = 0;
  struct ASNumberOrRangeA *asNumOrRangep = (struct ASNumberOrRangeA *)
    member_casn(&asNumbersOrRangesp->self, num_addr);
                                             // step 1
  struct iprange certrange, nextcertrange;
  cvt_asnum(&certrange, asNumOrRangep);
  struct iprange *constrangep = &iprangesp->iprangep[numrange];
  do
    {                                          // step 2
    if (!run)
      {
      while (certrange.hiASnum < constrangep->loASnum)
        {
        asNumOrRangep = (struct ASNumberOrRangeA *)next_of(
          &asNumOrRangep->self);
        cvt_asnum(&certrange, asNumOrRangep);
        }       
      if (constrangep->hiASnum < certrange.loASnum)  // case a
        {
        asNumOrRangep = (struct ASNumberOrRangeA *)
          inject_casn(&asNumbersOrRangesp->self, num_addr++);
        did += make_ASnum(asNumOrRangep, constrangep);
        asNumOrRangep = (struct ASNumberOrRangeA *)
          member_casn(&asNumbersOrRangesp->self, num_addr);
        }
      else if (constrangep->loASnum <= certrange.hiASnum)
        {
        struct ASNumberOrRangeA *nextasNumOrRangep = (struct ASNumberOrRangeA *)
          member_casn(&asNumbersOrRangesp->self, num_addr + 1);
        cvt_asnum(&nextcertrange, nextasNumOrRangep);
        if (constrangep->hiASnum < nextcertrange.loASnum)  // case b
          {
          certrange.hiASnum = constrangep->hiASnum;
          did += make_ASnum(asNumOrRangep, &certrange);
          }
        else                                        // case c
          {
          do
            {
            eject_casn(&asNumbersOrRangesp->self, num_addr);
            asNumOrRangep = (struct ASNumberOrRangeA *)member_casn(
              &asNumbersOrRangesp->self, num_addr);
            certrange.loASnum = constrangep->loASnum;
            }
          while (constrangep->hiASnum >= nextcertrange.loASnum);
          did += make_ASnum(asNumOrRangep, &certrange);
          }
        }
      if (certrange.loASnum <= constrangep->loASnum &&
          certrange.hiASnum >= constrangep->hiASnum) {}   // case d
      else if(constrangep->hiASnum >= certrange.loASnum)  // case e
        {
        certrange.loASnum = constrangep->loASnum;
        did += make_ASnum(asNumOrRangep, &certrange);
        }
      }
    else
      {
      while (certrange.hiASnum < constrangep->loASnum)
        {
        asNumOrRangep = (struct ASNumberOrRangeA *)
          member_casn(&asNumbersOrRangesp->self, ++num_addr);
        if (!asNumOrRangep) break;
        
        cvt_asnum(&certrange, asNumOrRangep); // convert cert address(es)
        }
                                                     // step 3
      while(asNumOrRangep && certrange.loASnum < constrangep->hiASnum)
        { 
        num_addr = perforate_ASNum(asNumbersOrRangesp, num_addr, &certrange, 
          constrangep, &did);
        did++;
        asNumOrRangep = (struct ASNumberOrRangeA *)
          member_casn(&asNumbersOrRangesp->self, ++num_addr);
        if (asNumOrRangep) cvt_asnum(&certrange, asNumOrRangep);
        }
      }
    constrangep++;  
    }
  while(constrangep);
  *changesp += did;
  return (constrangep - iprangesp->iprangep);
  }

static int run_through_IPlist(int run, struct ipranges *iprangesp, 
  int numrange, 
  struct AddressesOrRangesInIPAddressChoiceA *ipAddrOrRangesp, int *changesp)
  {
/*
Function: Reads through list of addresses and cert extensions to expand or 
perforate them.
inputs: typ: IPV4, IPV6
        run: 0 = expand, 1 = perforate,
        ptr to ipranges structure
        index to first iprange of this typ.  At least one guaranteed
        ptr to cert's space of this typ
Procedure:
1. Convert cert's starting address(es)
   DO
     IF expanding, expand cert
     ELSE
2.     WHILE cert hilim < constraint lolim
         Go to next item in cert, if any
3.     WHILE have a cert entry AND its lolim < constraint's hilim
         Perforate cert, noting need to flag old cert
         Go to next item in cert
     Get next constraint
   WHILE constraint is of current type
   Reconstruct IP addresses in cert from ipranges
   Note ending point in list
*/
  struct iprange *constrangep = &iprangesp->iprangep[numrange], 
    certrange;
  int typ = constrangep->typ;
  if (!ipAddrOrRangesp) return 0;
  int did = 0, lth = typ == IPV4? 4: 16, num_cert_item,
    num_cert_items = num_items(&ipAddrOrRangesp->self);
  struct IPAddressOrRangeA *ipAddrOrRangep = (struct IPAddressOrRangeA *)0;
  if (num_cert_items) ipAddrOrRangep = (struct IPAddressOrRangeA *)
    member_casn(&ipAddrOrRangesp->self, (num_cert_item = 0));
                                                  // step 1
       // convert cert address
  for ( ; constrangep->typ == typ; constrangep++)
    {
    if (!run) expand_cert(constrangep, ipAddrOrRangesp, changesp);
    else
      {                                              // step 2
      while(memcmp(certrange.hilim, constrangep->lolim, lth) < 0)
        {
        ipAddrOrRangep = (struct IPAddressOrRangeA *)
          member_casn(&ipAddrOrRangesp->self, ++num_cert_item);
        if (!ipAddrOrRangep) 
            cvt_asn(&certrange, ipAddrOrRangep); // convert cert address(es)
        }
                                                     // step 3
      while(ipAddrOrRangep && 
        memcmp(certrange.lolim, constrangep->hilim, lth) < 0)
        { 
        num_cert_item = perforate_cert(ipAddrOrRangesp, num_cert_item, 
          &certrange, constrangep, &did);
        ipAddrOrRangep = (struct IPAddressOrRangeA *)
          member_casn(&ipAddrOrRangesp->self, ++num_cert_item);
        if (ipAddrOrRangep) cvt_asn(&certrange, ipAddrOrRangep);
        }
      }
    }
  *changesp = did;
  return (constrangep - iprangesp->iprangep);
  }

static int modify_paracert(int run, struct ipranges *iprangesp, 
  struct Certificate *paracertp)
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
  int numrange = 0, typ, changes = 0;
    // start at beginning of SKI list and IPv4 family in certificate
  struct iprange *tiprangep = iprangesp->iprangep;   // beginning of SKI list
  struct Extension *extp = find_extension(&paracertp->toBeSigned.
    extensions, id_pe_ipAddrBlock, 0);  
                                                 // step 1
  typ = IPV4;  
  struct AddressesOrRangesInIPAddressChoiceA *ipAddrOrRangesp =
      find_IP(typ, extp);
  if (tiprangep->typ == typ &&
    (numrange = run_through_IPlist(run, iprangesp, 0, ipAddrOrRangesp, 
        &changes)) < 0); return numrange;
    
  typ = IPV6;                                       // step 2
  ipAddrOrRangesp = find_IP(typ, extp);
if (tiprangep->typ == typ &&
    (numrange = run_through_IPlist(run, iprangesp, numrange, 
      ipAddrOrRangesp, &changes)) < 0) return numrange;
 
  typ = ASNUM;                                     // step 3
  extp = find_extension(&paracertp->toBeSigned.extensions, 
    id_pe_autonomousSysNum, 0); 
  struct AsNumbersOrRangesInASIdentifierChoiceA *asNumbersOrRangesp = 
    &extp->extnValue.autonomousSysNum.asnum.asNumbersOrRanges;
  
  if (tiprangep->typ == typ  &&
    (numrange = run_through_ASlist(run, iprangesp, numrange,  
      asNumbersOrRangesp, &changes)) < 0) return numrange;
  return changes;
  }

static int search_downward(struct Certificate *topcertp, 
  struct ipranges *iprangesp)
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
      Punch out any listed resources
      IF any resources were punched out, add the cert & paracert to the list
        Add this cert to the done list
        Call this function with this child
*/
  struct Extension *extp = find_extension(&topcertp->toBeSigned.extensions,
      id_subjectKeyIdentifier, 0);
  struct Certificate *childcertp;
  int ansr, numkid, numkids;
  char skibuf[44];
  getAKI(skibuf, &extp->extnValue.subjectKeyIdentifier);
  
  // Get list of children having skibuf as their AKI
  for (ansr = numkid = 0; numkid < numkids && ansr >= 0; numkid++)
    {
    // childcertp = &children[numkid];
    extp = find_extension(&childcertp->toBeSigned.extensions,
      id_subjectKeyIdentifier, 0);
    getAKI(skibuf, &extp->extnValue.subjectKeyIdentifier);
    struct done_cert *done_certp, done_cert;
    int have = 0;
    if (!(done_certp = have_already(skibuf))) 
      {
      done_certp = &done_cert;
      strcpy(done_cert.ski, skibuf);
      done_certp->origcertp = childcertp;
      done_certp->paracertp =  mk_paracert(childcertp);
      }
    else have = 1;
    ansr = modify_paracert(1, iprangesp, done_certp->paracertp);
    if (have == 0)   // temp done_cert
      {
      if (ansr <= 0)
        {
        delete_casn(&done_certp->origcertp->self);
        delete_casn(&done_certp->paracertp->self);
        }
      }
    if (ansr > 0) ansr = search_downward(done_certp->origcertp, iprangesp);
    }
  return ansr;
  }

static int process_control_block(struct ipranges *iprangesp, 
  struct done_cert *done_certp)
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
     Get that parent cert (and make paracert if necessaru
4. FOR all other self-signed certificates, search downward perforating them
   Return 0
*/
                                              // step 1
  struct Certificate *paracertp;
  int run = 0;
  struct Extension *extp;
  struct done_cert *ndone_certp = (struct done_cert *)0;
  for (run = 0; 1; run++) 
    {
    int ansr;
    if (!done_certp->perf || !run) return -1; // usage conflict
    if ((ansr = modify_paracert(run, iprangesp, paracertp)) < 0)
      return ansr;
                                                  // step 2
    if (!diff_casn(&done_certp->origcertp->toBeSigned.issuer.self, 
       &done_certp->origcertp->toBeSigned.subject.self)) break;
                                                        // step 3     
    extp = find_extension(&paracertp->toBeSigned.extensions,
      id_authKeyId, 0);
    char skibuf[SKIBUFSIZ];  // put AKI in skibuf
    getAKI(skibuf, &extp->extnValue.authKeyId.keyIdentifier);
    if ((ansr = get_CAcert(skibuf, &ndone_certp)) < 0) return ansr;
    
    } 
    // oldcert is at a self-signed cert
  // for all ss certs
  search_downward(done_certp->origcertp, iprangesp);
  return 0;
  }

static int process_control_blocks(FILE *SKI, char *skibuf) 
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
       Log error
       Skip to next SKI block
     Process the block
   WHILE skibuf has anything   
*/
  struct done_cert *done_certp;
  int ansr = 1;
  do
    {
    char *cc, *skip;
    for (skip = &skibuf[4]; *skip == ' '; skip++);
    for (cc = skip; (*cc >= '0' && *cc <= '9') || 
        ((*cc | 0x20) >= 'a' && (*cc | 0x20) <= 'f'); cc++);
    if ((cc - skip) != 40 || *cc > ' ') return -1; // BADSKIBLOCK
    *cc = 0;
    if ((ansr = get_CAcert(skip, &done_certp)) < 0)
      {
      // log error
      while ((cc = fgets(skibuf, SKIBUFSIZ, SKI)) && *skibuf != 'S')
      if (!cc) return -1;  // NOCERTCHAIN
      }
    else
      {    
      struct ipranges ipranges;
      ipranges.numranges = 0;
      ipranges.iprangep = (struct iprange *)0;
      if ((ansr = getSKIBlock(SKI, skibuf, &ipranges)) < 0) 
          return -1; // with error message in skibuf BADSKIBLOCK
         // otherwise skibuf has another SKI line or NULL
      int err;
      
      if ((err = process_control_block(&ipranges, done_certp))) 
        return err;
      }
    }
  while(ansr);
  return 0;
  } 

static int read_SKI_blocks(char *skiblockfile, int flags)
  {
/*
Procedure:
1. Open file for control data
   Get certificate for RP
   Get key nformation for RP
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
  char *c, *cc, skibuf[SKIBUFSIZ];
                                                     // step 1
  int flag = 0, ansr = 0;
  locflags = flags;
  FILE *SKI;
  done_certs.numcerts = 0;

  if (!(SKI = fopen(skiblockfile, "r"))) ansr = -1; // can't open
  else if (!fgets(skibuf, sizeof(skibuf), SKI)) ansr = -1;  // no RP certificate
  else
    {
    c = strchr(skibuf, (int)'\n');
    if (c) *c = 0;
    if (get_casn_file(&myrootcert.self, skibuf, 0) < 0) ansr = -1; // bad root  
    else if(!fgets(skibuf, sizeof(skibuf), SKI)) ansr = -1;  // RP key file
        // get RP key ???
    else if(!(c = fgets(skibuf, sizeof(skibuf), SKI))) ansr = -1; // short file 
    else
      {
      while (c && !ansr && !strncmp(skibuf, "CONTROL", 7))  
        {
        for (cc = &skibuf[7]; *cc >= ' '; cc++);
        *cc = 0;
        for (cc--; *cc > ' '; cc--);
        cc++;
        if (!strcmp(cc, "intersection_always")) flag |= INTERSECTION_ALWAYS;
        else if (!strcmp(cc, "resource_nounion")) flag |= RESOURCE_NOUNION;
        else ansr = -1;
        c = fgets(skibuf, sizeof(skibuf), SKI);
        }
      if (!c || strncmp(skibuf, "SKI ", 4)) ansr = -1; // short file
      else ansr = process_control_blocks(SKI, skibuf);
      }
    }
  int numcert;
  struct done_cert *done_certp = done_certs.done_certp;
  for (numcert = 0; numcert < done_certs.numcerts; numcert++, done_certp++)
    {
    // mark done_certp->SKI cert as having para
    // sign done_certp->paracertp
    // put in database with para flag
    delete_casn(&done_certp->origcertp->self);
    delete_casn(&done_certp->paracertp->self);
    free(done_certp->origcertp);
    free(done_certp->paracertp);
    }
  fclose(SKI);
  delete_casn(&myrootcert.self);
  return ansr;
  }
