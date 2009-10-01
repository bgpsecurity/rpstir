#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <certificate.h>
#include <casn.h>

#define IPV4 4
#define IPV6 6
#define ASNUM 8

struct iprange
  {
  int typ;
  uchar lolim[18], hilim[18];
  ulong loASnum, hiASnum;
  char *text;
  };

void count_bits(struct iprange *, int *, int *),
    cvt_asn(struct iprange *torangep, struct IPAddressOrRangeA *asnp),
    cvt_asnum(struct iprange *certrangep, 
        struct ASNumberOrRangeA *asNumberOrRangeA),
    decrement_iprange(uchar *lim, int lth),
    increment_iprange(uchar *lim, int lth);

int diff_ipaddr(struct iprange *, struct iprange *),
    overlap(struct iprange *lop, struct iprange *hip),
    txt2loc(int typ, char *skibuf, struct iprange *iprangep);

