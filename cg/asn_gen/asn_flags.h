/* $Id$ */
/* May 26 2004 768U  */
/* May 26 2004 GARDINER moved BOOL flags to asn_flags.h */
/* May 25 2004 767U  */
/* May 25 2004 GARDINER added ASN_SET_FLAG */
/* May 25 2004 766U  */
/* May 25 2004 GARDINER added ASN_LAST_FLAG */
/* May 25 2004 765U  */
/* May 25 2004 GARDINER moved flags to asn_flags.h */
/*****************************************************************************
File:     asn_flags.h
Contents: Definitions of flags for asn_(c)gen, asn_obj and casn
System:   ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

COPYRIGHT 2004 BBN Technologies
10 Moulton St.
Cambridge, Ma. 02140
617-873-4000
*****************************************************************************/
#ifndef _ASN_FLAGS_H
#define _ASN_FLAGS_H
/* sfcsid[] = "@(#)asn_flags.h 768P" */
/* AsnObj flags defines */
#define ASN_FILLED_FLAG    1
#define ASN_POINTER_FLAG   2
#define ASN_OPTIONAL_FLAG  4
#define ASN_OF_FLAG        8
/* #define ASN_CHOICE_FLAG 0x10 */
#define ASN_FALSE_FLAG  0x20        /* used only in asn_gen */
#define ASN_SUB_INDEF_FLAG 0x20     /* used only in C++ */
#define ASN_TABLE_FLAG  0x40
#define ASN_DUPED_FLAG  0x80
#define ASN_SET_FLAG    0x80        /* used only in casn */
#define ASN_CONSTRAINT_FLAG 0x100   /* used only in asn_gen */
#define ASN_LAST_FLAG    0x100      /* used only in casn */
#define ASN_DEFAULT_FLAG 0x200
#define ASN_RANGE_FLAG   0x400      /* used in asn_cgen and casn.c */
#define ASN_DEFINED_FLAG 0x800
#define ASN_CHOSEN_FLAG  0x1000     /* used only in C++ */
#define ASN_DEFINER_FLAG 0x1000     /* used only in asn_gen */
#define ASN_EXPORT_FLAG  0x2000     /* used only in asn_gen */
#define ASN_INDEF_LTH_FLAG 0x2000   /* used only in C++ */
#define ASN_EXPLICIT_FLAG 0x4000
#define ASN_ENUM_FLAG     0x8000

/* BOOLEAN default masks */
#define BOOL_DEFAULT    1   /* value of default */
#define BOOL_DEFINED    2   /* flag indicating if table specifies a value */
#define BOOL_DEFINED_VAL 4  /* value if table specifies a value     */

#endif
