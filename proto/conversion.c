#include "conversion.h"

void cvt_asn(struct iprange *torangep, struct IPAddressOrRangeA *asnp)
  {
  struct casn *locasn, *hicasn;
  if (vsize_casn(&asnp->addressPrefix)) locasn = hicasn =  &asnp->addressPrefix;
  else
    {
    locasn = &asnp->addressRange.min;
    hicasn = &asnp->addressRange.max;
    }
  uchar locbuf[20];
  int siz = read_casn(locasn, locbuf) - 1;
  memset(torangep->lolim, 0, sizeof(torangep->lolim));
  memcpy(torangep->lolim, &locbuf[1], siz);
  siz = read_casn(hicasn, locbuf) - 1;
  memset(torangep->hilim, -1, sizeof(torangep->hilim));
  memcpy(torangep->hilim, &locbuf[1], siz);
         // fill in unused bits in last byte with ones
  if (locbuf[0]) torangep->hilim[siz - 1] |= ((1 << locbuf[0]) - 1);
  }

static ulong casn2ulong(struct casn *casnp)
  {
  uchar locbuf[4], *uc;
  ulong ansr;
  int lth = read_casn(casnp, locbuf);
  for (ansr = 0, uc = &locbuf[lth]; --uc >= locbuf; )
    {
    ansr <<= 8;
    ansr += *uc;
    }
  return ansr;
  }

void count_bits(struct iprange *tiprangep, int *lonump, int *hinump)
  {
/*
Procedure:
1. Running from right to left, find where the low and high of tiprangep differ
   Count the number of bits where they match
*/
  int lth = tiprangep->typ == IPV4? 4: 16;
  uchar *hucp, *lucp, mask;
  int lonumbits, hinumbits;
  lonumbits = hinumbits = (lth << 3);
                                                   // step 1
  for (lucp = &tiprangep->lolim[lth - 1], lonumbits = lth << 3;
      lucp >= tiprangep->lolim && !*lucp; 
    lucp--,  lonumbits -= 8);
  if (lucp >= tiprangep->lolim)
    {
    for (mask = 1; mask && !(mask & *lucp); mask <<= 1, lonumbits--);
    } 
  for (hucp = &tiprangep->hilim[lth - 1], hinumbits = 0 ; 
    hucp >= tiprangep->hilim && *hucp == 0xFF; hucp--, hinumbits += 8);
  if (hucp >= tiprangep->hilim)
    {
    for (mask = 1; mask  && (mask & *hucp); mask <<= 1, hinumbits--);
    }
  *lonump = lonumbits;
  *hinump = hinumbits;
  }

void cvt_asnum(struct iprange *certrangep, 
  struct ASNumberOrRangeA *asNumberOrRangep)
  {
  if (size_casn(&asNumberOrRangep->num) > 0)
    {
    certrangep->hiASnum = certrangep->loASnum =
        casn2ulong(&asNumberOrRangep->num);
    }
  else
    {
    certrangep->loASnum = casn2ulong(&asNumberOrRangep->range.min);
    certrangep->hiASnum = casn2ulong(&asNumberOrRangep->range.max);
    }
  }

static int cvtv4(uchar fill, char *ip, uchar *buf)
  {
  uchar *uc, *ue = &buf[4];
  char *c;
  int fld;
  for (c = ip; *c > ' ' && ((*c >= '0' && *c <= '9') || 
    *c == '.' || *c == '/');
    c++);
  if (*c > ' ') return -2;
  memset(buf, fill, 4);
  for (c = ip, uc = buf; *c && *c != '/'; )
    {
    if (*c == '.') c++;
    sscanf(c, "%d", &fld);
    if (uc >= ue || fld > 255) return -1;
    *uc++ = (uchar)fld;
    while (*c != '.' && *c != '/') c++;
    }
  if (*c) 
    {
    uchar mask;
    c++;
    sscanf(c, "%d", &fld); // fld has total number of bits
    if (fld >= 32) return (fld > 32)? -1: 0;
    uc = &buf[(fld >> 3)];  // points to char having bit beyond last
    fld %= 8;   // number of used bits in last byte
    fld = 8 - fld;   // number of unused 
    mask = ~(0xFF << fld);  // mask for last byte
    if (fill) 
      {
      mask = ~mask;
      if ((mask & *uc)) return -1;
      *uc |= (~mask);
      }
    else 
      {
      if ((mask & *uc)) return -1;
      *uc &= mask;
      }
    }
  return 0;
  }
    
static int cvtv6(uchar fill, char *ip, uchar *buf)
  {
  uchar *up, *ue;
  char *c;
  int fld, elided;
  for (c = ip; *c > ' ' && ((*c >= '0' && *c <= '9') || 
    ((*c | 0x20) >= 'a' && (*c | 0x20) <= 'f') || *c == ':' || *c == '/');
    c++);
  if (*c > ' ') return -2;
  for (up = buf, ue = &buf[16]; up < ue; *up++ = fill);
  for (c = ip, elided = 8; *c && *c != '/'; c++)
    {
    if (*c == ':') elided--;
    } 
  for (c = ip, up = buf; *c > ' ' && *c != '/';)
    {
    if (*c == ':') c++;
    sscanf(c, "%x", &fld);
    if (up >= ue || fld > 0xFFFF) return -1;
    *up++ = (uchar)((fld >> 8) &0xFF);
    *up++ = (uchar)(fld & 0xFF);
    while(*c && *c != ':' && *c != '/') c++;
    if (*c == ':' && c[1] == ':')
      {
      while(elided) 
        {
        *up++ = 0;
        *up++ = 0;
        elided--;
        }
      c++;
      }
    }
  if (*c) 
    {
    ushort mask;
    c++;
    sscanf(c, "%d", &fld); // fld has total number of bits
    if (fld >= 128) return (fld > 128)? -1: 0;
    up = &buf[(fld >> 3)];
    fld %= 16;   // number of used bits in last ushort
    fld = 16 - fld;  // number of unused bits
    mask = (0xFFFF << fld);  // mask for last ushort
    if (fill) 
      {
      mask = ~mask;
          // if up is at the high byte in a short
      if (!((up - buf) & 1)) *up++ |= ((mask >> 8) & 0xFF);
      *up |= (mask & 0xFF);
      }
    else 
      {
      *up++ &= ((mask >> 8) & 0xFF);
      *up   &= (mask & 0xFF);
      }
    }
  return 0;
  }

void  decrement_iprange(uchar *lim, int lth)
  {
  uchar *ucp;
  for (ucp = &lim[lth - 1]; ucp >= lim && *ucp == 0; *ucp-- = 0xFF);
      // uc now at last non-zero
  if (ucp >= lim) (*ucp)--;
  }

void increment_iprange(uchar *lim, int lth)
  {
  uchar *ucp;
  for (ucp = &lim[lth - 1]; ucp >= lim && *ucp == 0xff; *ucp-- = 0);
  if (ucp >= lim) (*ucp)++;
  }

int diff_ipaddr(struct iprange *lop, struct iprange *hip)
  {
  int ansr;
  if (lop->typ > 0)
    {
    ansr = memcmp(lop->lolim, hip->lolim, (lop->typ == IPV4)? 4: 16);
    }
  else
    {
    if((hip->hiASnum == hip->loASnum && lop->loASnum == lop->hiASnum) ||
       hip->loASnum > lop->hiASnum)
       ansr = lop->loASnum - hip->hiASnum;
    else ansr = 0; 
    }
  return ansr;
  }

int overlap(struct iprange *lop, struct iprange *hip)
  {
  if (lop->typ != hip->typ) return 0;
  if (lop->typ > 0)
    {
    int lth = lop->typ == IPV4? 4: 16;
    if ((memcmp(lop->lolim, hip->lolim, lth) > 0 &&  // lolo within hi
         memcmp(lop->lolim, hip->hilim, lth) < 0) ||
        (memcmp(lop->hilim, hip->lolim, lth) > 0 &&  // lohi within hi
         memcmp(lop->hilim, hip->hilim, lth) < 0) ||

        (memcmp(hip->lolim, lop->lolim, lth) > 0 &&  // hilo within lo
         memcmp(hip->lolim, lop->hilim, lth) < 0) ||
        (memcmp(hip->hilim, lop->lolim, lth) > 0 &&  // hihi within lo
         memcmp(hip->hilim, lop->hilim, lth) < 0))
         return -1;
    }
  return 0;
  }

int  txt2loc(int typ, char *skibuf, struct iprange *iprangep)
  {
  int ansr;
  char *c;
  iprangep->typ = typ;
  if (typ == ASNUM)
    {
    for (c = skibuf; *c > ' ' && *c >= '0' && *c <= '9'; c++);
    if (*c > ' ') return -2; 
    sscanf(skibuf, "%ld", &iprangep->loASnum);
    iprangep->hiASnum = iprangep->loASnum;
    }
  else if (typ == IPV4) 
    {
    if ((ansr = cvtv4((uchar)0,    skibuf, iprangep->lolim)) < 0 ||
      (ansr = cvtv4((uchar)0xff, skibuf, iprangep->hilim)) < 0) 
      return ansr;
    }
  else if (typ == IPV6)
    {
    if ((ansr = cvtv6((uchar)0,  skibuf, iprangep->lolim)) < 0 ||
      (ansr = cvtv6((uchar)0xff, skibuf, iprangep->hilim)) < 0) 
      return ansr;
    }
  else return -1;
  return 0;
  }
