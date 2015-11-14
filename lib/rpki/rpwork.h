#ifndef LIB_RPKI_RPWORK_H
#define LIB_RPKI_RPWORK_H

#include "err.h"
#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "diru.h"
#include "myssl.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <rpki-asn1/cms.h>
#include <util/cryptlib_compat.h>
#include <rpki-asn1/keyfile.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <rpki-object/certificate.h>
#include <casn/casn.h>
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

struct cert_ansr {
    char dirname[PATH_MAX];
    char filename[PATH_MAX];
    char fullname[PATH_MAX];
    char aki[120];
    char issuer[PATH_MAX];
    unsigned int flags;
    unsigned int local_id;
};

struct cert_answers {
    /**
     * If negative, this is an error code value from ::err_code.
     */
    int num_ansrs;
    struct cert_ansr *cert_ansrp;
};

struct iprange {
    int typ;
    uchar lolim[18];
    uchar hilim[18];
    ulong loASnum;
    ulong hiASnum;
    char *text;
};

struct ipranges {
    int numranges;
    struct iprange *iprangep;
};
#define IPRANGES_EMPTY_INITIALIZER {0, NULL}

struct done_cert {
    char ski[64];
    int perf;
    ulong origID;
    ulong origflags;
    char filename[PATH_MAX];
    struct Certificate *origcertp;
    struct Certificate *paracertp;
};

struct done_certs {
    int numcerts;
    struct done_cert *done_certp;
};

extern char *Xaia;
struct validity_dates {
    struct casn lodate;
    struct casn hidate;
} Xvaliddates;

struct keyring {
    char *filename;
    char *label;
    char *password;
};

void
cvt_asn(
    struct iprange *torangep,
    struct IPAddressOrRangeA *asnp);

void
cvt_asnum(
    struct iprange *certrangep,
    struct ASNumberOrRangeA *asNumberOrRangeA);

void
mk_certranges(
    struct ipranges *,
    struct Certificate *);

void
decrement_iprange(
    uchar *lim,
    int lth);

void
increment_iprange(
    uchar *lim,
    int lth);

void
clear_ipranges(
    struct ipranges *);

struct iprange *
eject_range(
    struct ipranges *,
    int);

struct iprange *
inject_range(
    struct ipranges *,
    int);

struct iprange *
next_range(
    struct ipranges *,
    struct iprange *);

void
free_ipranges(
    struct ipranges *);

char *
nextword(
    char *);

char myrootfullname[PATH_MAX];

err_code
parse_SKI_blocks(
    struct keyring *,
    FILE *,
    const char *,
    char *,
    int,
    int *);

err_code
get_CAcert(
    char *,
    struct done_cert **);

err_code
getSKIBlock(
    FILE *,
    char *,
    int);

int
check_date(
    char *datep,
    struct casn *casnp,
    int64_t *datenump);

int
check_dates(
    char *datesp);

int
check_jetring(
    char *);

int
sort_resources(
    struct iprange *,
    int);

int
touches(
    struct iprange *,
    struct iprange *,
    int);

int
diff_ipaddr(
    struct iprange *,
    struct iprange *);

int
overlap(
    struct iprange *lop,
    struct iprange *hip);

int
txt2loc(
    int,
    char *,
    struct iprange *);

#endif
