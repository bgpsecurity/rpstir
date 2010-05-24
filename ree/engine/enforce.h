/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Rule Editor/Engine for Address and AS Number PKI
 * Verison 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE—RESTRICTED RIGHTS (JUNE 1987)
 * US government users are permitted restricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 2007.  All Rights Reserved.
 *
 * Contributor(s):  Charlie Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

/* $Id$ */

#define uchar unsigned char
#ifndef ushort                          /* sys/types.h defines it, too */
#define ushort unsigned short
#endif
#define ulong unsigned long

struct asn
    {
    uchar *stringp;
    ulong lth;
    ushort level;
#ifdef SUN
    ushort pad;
#endif
    };

struct fasn
    {
    uchar *stringp;
    ulong lth;
    ushort level;
#ifdef SUN
    ushort pad;
#endif
    };

#define GET_FILE_ASN_REF(x) x->stringp
#define ROUND4(x)  (uchar *)(((int)x + 3) & ~3) /* made 3 for sparc */
#define FULL_LENGTH(a) (uchar *)asn_start(a) - a->stringp + a->lth
#define ASN_INDEF_FLAG 0x8000	/* used in asn.level to show indef length */

#define ASN_INDEF_LTH        0x80
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

#define RULE_SEQUENCE_TAG   (ASN_PRIV_CONSTR) + 0
#define RULE_SET_TAG        (ASN_PRIV_CONSTR) + 1
#define RULE_SEQUENCED_TAG  (ASN_PRIV_CONSTR) + 2
#define RULE_SEQOF_TAG      (ASN_PRIV_CONSTR) + 3
#define RULE_SETOF_TAG      (ASN_PRIV_CONSTR) + 4
#define RULE_CHOICE_TAG     (ASN_PRIV_CONSTR) + 5
#define RULE_DEFINEDBY_TAG  (ASN_PRIV_CONSTR) + 6
#define RULE_RULE_TAG       (ASN_PRIV_CONSTR) + 7
#define RULE_RULED_TAG      (ASN_PRIV_CONSTR) + 8
#define RULE_DATE_TAG       (ASN_PRIV_CONSTR) + 9
#define RULE_NAMEDBITS_TAG  (ASN_PRIV_CONSTR) + 10
#define RULE_FILEREF_TAG    (ASN_PRIV_CONSTR) + 11
#define RULE_WRAPPER_TAG    (ASN_PRIV_CONSTR) + 12
#define RULE_SPECIAL_TAG    (ASN_PRIV_CONSTR) + 13
#define LAST_RULE_TAG       (RULE_SPECIAL_TAG) /* must match tag of last rule */

#define UTCBASE 70
#define UTCYR 0
#define UTCYRSIZ 2
#define UTCMO (UTCYR + UTCYRSIZ)
#define UTCMOSIZ 2
#define UTCDA  (UTCMO + UTCMOSIZ)
#define UTCDASIZ 2
#define UTCHR  (UTCDA + UTCDASIZ)
#define UTCHRSIZ 2
#define UTCMI  (UTCHR + UTCHRSIZ)
#define UTCMISIZ 2
#define UTCSE (UTCMI + UTCMISIZ)
#define UTCSESIZ 2
#define UTCSFXHR 1
#define UTCSFXMI (UTCSFXHR + UTCHRSIZ)
#define UTCT_SIZE 16
#define GENTBASE (1900 + UTCBASE)
#define GENTYR 0
#define GENTYRSIZ 4
#define GENTSE (UTCSE + GENTYRSIZ - UTCYRSIZ)

#define NO_ERR 0
#define BAD_ASN1 1
#define FAIL_RULE 2
#define BAD_RULE 3

#define HASH_FIRST 1
#define HASH_LAST  2
#define HASH_BOTH 3

#define id_forbid 0
#define id_allow 1
#define id_require 2
#define id_part_forbid 3
#define id_part_allow 4
#define id_set_num 1
#define id_check_CRLNum 2
#define id_subordinate 3
#define id_keyIDMethod 4
#define id_isForCA 5
#define id_allowIFFCA 6
#define id_limits 7
#define id_addrRanges 8
#define id_key_snum 1
#define id_key_sha1 2
#define id_key_trunc_sha1 3
#define id_key_uniq_val 4


extern ulong get_asn_gentime(struct asn *asnp),
        get_asn_time(struct asn *asnp);

extern uchar *asn_start(struct asn *asnp),
    *fasn_start(struct fasn *fasnp);

extern uchar *so_free, *eoram, *ca_namep,
    *asn_setup(struct asn *);

extern int ca_name_lth, make_asn_table(struct asn **, uchar *, ulong);

extern char *verbose;

extern struct asn *issuer_asnp,
    *rfile_asnbase,
    *skip_asn(struct asn *, struct asn *, int);

extern struct fasn *skip_fasn(struct fasn *, struct fasn*, int);

extern void fatal(int, char *);
