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

#define IPv4 4
#define IPv6 6
#define ASNUM 8

struct cert_ansr
  {
  char dirname[PATH_MAX], filename[PATH_MAX], fullname[PATH_MAX];
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

void cvt_asn(struct iprange *torangep, struct IPAddressOrRangeA *asnp),
    cvt_asnum(struct iprange *certrangep,
        struct ASNumberOrRangeA *asNumberOrRangeA),
    decrement_iprange(uchar *lim, int lth),
    increment_iprange(uchar *lim, int lth);

extern int diff_ipaddr(struct iprange *, struct iprange *),
    overlap(struct iprange *lop, struct iprange *hip),
    txt2loc(int typ, char *skibuf, struct iprange *iprangep);
#endif

