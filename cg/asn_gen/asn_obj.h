/* $Id$ */
/*****************************************************************************
File:     asn_obj.h
Contents: Header file for the ASN_GEN program and the basic library
        functions.
System:   ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

*****************************************************************************/
#ifndef _ASN_OBJ_H
#define _ASN_OBJ_H
/* $Header: /nfs/sub-rosa/u2/IOS_Project/ASN/Dev/rcs/lib/asn_obj/asn_obj.h,v 1.2 1995/01/11 22:23:42 jlowry Exp gardiner $ */
/* sfcsid[] = "@(#)asn_obj.h 805P" */

#ifndef CPM         /* do not include if cross-compiling */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "asn.h"
#include "asn_timedefs.h"

#ifndef WIN32
#include <unistd.h>
#else
#include <io.h>
#endif

#include "asn_flags.h"

extern int asn_errno;
extern ulong decode_asn_lth(const uchar **), decode_asn_tag(const uchar **);
extern char asn_map_string[];
extern const uchar *asn_constraint_ptr;
extern void stuff(int);
#endif /* CPM */

/* char_table masks */
#define ASN_NUMERIC_MASK  1
#define ASN_PRINTABLE_MASK 4
#define ASN_T61_MASK       8
#define ASN_IA5_MASK      0x10

/* built-in object identifiers */
#define ccitt   0
#define itu_t   0
#define iso     1
#define joint_ios_ccitt 2
#define joint_iso_itu_t 2
#define standard    0
#define member_body 2
#define identified_organization 3

#endif /* _ASN_OBJ_H */
