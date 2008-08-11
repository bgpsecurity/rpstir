/* $Id$ */
/*****************************************************************************
File:     asn.h
Contents: Header file for basic ASN.1 functions.
System:   ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

 ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE RESTRICTED RIGHTS (JUNE 1987)
 * US government users are permitted restricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 1995-2007.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK *****
*****************************************************************************/
/* sfcsid[] = "@(#)asn.h 824P" */
#ifndef _ASN_H
#define _ASN_H

#define uchar unsigned char
#ifndef ushort
#define ushort unsigned short
#endif
#define ulong unsigned long

#define ASN_ANY              0
#define ASN_BOOLEAN          1
#define ASN_INTEGER          2
#define ASN_BITSTRING        3
#define ASN_OCTETSTRING      4
#define ASN_NULL             5
#define ASN_OBJ_ID           6
#define ASN_EXTERNAL         8
#define ASN_REAL             9
#define ASN_ENUMERATED       10
#define ASN_UTF8_STRING      12
#define ASN_RELATIVE_OID     13
#define ASN_NUMERIC_STRING   0x12
#define ASN_PRINTABLE_STRING 0x13
#define ASN_T61_STRING       0x14
#define ASN_VIDEOTEX_STRING  0x15
#define ASN_IA5_STRING       0x16
#define ASN_UTCTIME          0x17
#define ASN_GENTIME          0x18
#define ASN_GRAPHIC_STRING   0x19
#define ASN_VISIBLE_STRING   0x1A
#define ASN_GENERAL_STRING   0x1B
#define ASN_UNIVERSAL_STRING 0x1C
#define ASN_BMP_STRING       0x1E
#define ASN_XT_TAG           0x1F
#define ASN_CONSTRUCTED      0x20
#define ASN_INSTANCE_OF      0x28
#define ASN_SEQUENCE         0x30
#define ASN_SET              0x31
#define ASN_APPL_SPEC        0x40
#define ASN_APPL_CONSTR      (ASN_APPL_SPEC | ASN_CONSTRUCTED)
#define ASN_CONT_SPEC        0x80
#define ASN_CONT_CONSTR      (ASN_CONT_SPEC | ASN_CONSTRUCTED)
#define ASN_CONT_SPEC0       (ASN_CONT_SPEC | ASN_CONSTRUCTED) /* bwds compat */
#define ASN_PRIV_SPEC        0xC0
#define ASN_PRIV_CONSTR      (ASN_PRIV_SPEC | ASN_CONSTRUCTED)
#define ASN_INDEF_LTH        0x80
#define ASN_INDEF            ASN_INDEF_LTH
#define ASN_CHOICE           (0x100 | ASN_CONSTRUCTED)
#define ASN_NONE             0x101
#define ASN_FUNCTION         0x102
#define ASN_NOTASN1          0x103
#define ASN_NOTYPE           0x104

#ifndef __cplusplus

#define ASN_INDEF_FLAG 0x8000   /* used in asn.level to show indef length */

struct asn
    {
    uchar *stringp;
    ulong lth;
    ushort level;
#ifdef SUN
    ushort pad;
#endif
    };

struct typnames
    {
    unsigned char typ;
    char *name;
    };

#endif
#endif /* _ASN_H */
