/*
  $Id: rpwork.h 888 2009-11-17 17:59:35Z gardiner $
*/

#ifndef _RPWORK_H
#define _RPWORK_H
#include "err.h"
#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "diru.h"
#include "myssl.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <roa.h>
#include <cryptlib.h>
#include <keyfile.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <certificate.h>
#include <casn.h>
#include "sqhl.h"

#define IPv4 4
#define IPv6 6
#define ASNUM 8

#define TREEGROWTH               1
#define RESOURCE_NOUNION         2
#define INTERSECTION_ALWAYS      4
#define PARACERT              0x40  
#define WASEXPANDED           0x80
#define WASPERFORATED        0x100
#define WASEXPANDEDTHISBLK   0x200
#define WASPERFORATEDTHISBLK 0x400
#define HASPARA_INDB         0x800
#define SKIBUFSIZ    128
struct cert_ansr
  {
  char dirname[PATH_MAX], filename[PATH_MAX], fullname[PATH_MAX],
    aki[120], issuer[PATH_MAX];
  unsigned int flags;
  unsigned int local_id;
  };

struct cert_answers
  {
  int num_ansrs;
  struct cert_ansr *cert_ansrp;
  };

struct iprange
  {
  int typ;
  uchar lolim[18], hilim[18];
  char *text;
  };

struct ipranges
  {
  int numranges;
  struct iprange *iprangep;
  };
#define IPRANGES_EMPTY_INITIALIZER {0, NULL}

struct done_cert
  {
  char ski[64];
  int perf;
  ulong origID, origflags;
  char filename[PATH_MAX];
  struct Certificate *origcertp, *paracertp;
  };

struct done_certs
  {
  int numcerts;
  struct done_cert *done_certp;
  };

extern char *Xaia;
struct validity_dates
  {
  struct casn lodate;
  struct casn hidate;
  } Xvaliddates;

struct keyring
  {
  char *filename;
  char *label;
  char *password;
  };

void cvt_asn(struct iprange *torangep, struct IPAddressOrRangeA *asnp),
    cvt_asnum(struct iprange *certrangep,
        struct ASNumberOrRangeA *asNumberOrRangeA),
    mk_certranges(struct ipranges*, struct Certificate *),
    decrement_iprange(uchar *lim, int lth),
    increment_iprange(uchar *lim, int lth),
    clear_ipranges(struct ipranges *);

struct iprange *eject_range(struct ipranges *, int ),
      *inject_range(struct ipranges *, int),
      *next_range(struct ipranges *, struct iprange *);

extern void free_ipranges(struct ipranges *);

struct Extension *find_extn(struct Certificate *certp, char *oid, int add);

char *nextword(char *), myrootfullname[PATH_MAX];

int parse_SKI_blocks(FILE *, char *, int, int *), 
  get_CAcert(char *, struct done_cert **),
  getSKIBlock(FILE *, char *, int), 
  check_date(char *datep, struct casn *casnp, int64_t *datenump),
  check_dates(char *datesp), check_jetring(char *),
  sort_resources(struct iprange *, int),
  touches(struct iprange *, struct iprange *, int); 

extern int diff_ipaddr(struct iprange *, struct iprange *),
    overlap(struct iprange *lop, struct iprange *hip),
    txt2loc(int , char *, struct iprange *);
#endif

