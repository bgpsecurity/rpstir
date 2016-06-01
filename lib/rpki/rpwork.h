#ifndef LIB_RPKI_RPWORK_H
#define LIB_RPKI_RPWORK_H

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <casn/casn.h>

#define IPv4 4
#define IPv6 6
#define ASNUM 8

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

int
txt2loc(
    int,
    char *,
    struct iprange *);

#endif
