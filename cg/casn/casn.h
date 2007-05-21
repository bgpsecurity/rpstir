/* $Id$ */
/* Feb 15 2006 830U  */
/* Feb 15 2006 GARDINER changed return from inject_casn & insert_casn */
/* Apr 25 2005 828U  */
/* Apr 25 2005 GARDINER added inject, eject and member */
/* Jan 13 2005 822U  */
/* Jan 13 2005 GARDINER added reals */
/* Jan  4 2005 819U  */
/* Jan  4 2005 GARDINER changed level to ushort in constructors */
/* Jan  4 2005 818U  */
/* Jan  4 2005 GARDINER added simple_constructor and tagged_constructor */
/* Sep  1 2004 803U  */
/* Sep  1 2004 GARDINER added encodesize_casn, readvsize_casn and readvsize_objid */
/* Aug  3 2004 795U  */
/* Aug  3 2004 GARDINER changed err_struct to casn_err_struct */
/* Jul 14 2004 780U  */
/* Jul 14 2004 GARDINER removed mask from clear_casn */
/* Jul 13 2004 779U  */
/* Jul 13 2004 GARDINER revised next_of */
/* Jul  8 2004 777U  */
/* Jul  8 2004 GARDINER added next_of */
/* Jun 21 2004 776U  */
/* Jun 21 2004 GARDINER added diff_objid */
/* Jun 14 2004 774U  */
/* Jun 14 2004 ROOT added CONSTRAINTS */
/* Jun  3 2004 771U  */
/* Jun  3 2004 GARDINER fixed warnings */
/* May 25 2004 765U  */
/* May 25 2004 GARDINER moved flags to asn_flags.h */
/* May 21 2004 764U  */
/* May 21 2004 GARDINER more fixes for asn_obj tests */
/* Apr 21 2004 761U  */
/* Apr 21 2004 GARDINER fixed for half of casn_obj testing */
/* Apr 15 2004 759U  */
/* Apr 15 2004 GARDINER made decode_casn take no length */
/* Mar 25 2004 744U  */
/* Mar 25 2004 GARDINER fixed warnings */
/* Mar 25 2004 743U  */
/* Mar 25 2004 GARDINER started */
/* sfcsid[] = "@(#)casn.h 830P" */
/*****************************************************************************
File:     casn.h
Contents: Basic definitions
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

COPYRIGHT 2004 BBN Systems and Technologies
10 Moulton St.
Cambridge, Ma. 02138
617-873-3000
*****************************************************************************/

#ifndef _casn_h
#define _casn_h
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include "asn.h"
#include "asn_flags.h"

// error codes
#define ASN_MATCH_ERR       1
#define ASN_MEM_ERR         2
#define ASN_GEN_ERR         3
#define ASN_CHOICE_ERR      4
#define ASN_OF_ERR          5
#define ASN_MANDATORY_ERR   6
#define ASN_NOT_OF_ERR      7
#define ASN_OF_BOUNDS_ERR   8
#define ASN_EMPTY_ERR       9
#define ASN_DEFINER_ERR     10
#define ASN_NO_DEF_ERR      11
#define ASN_BOUNDS_ERR      12
#define ASN_TYPE_ERR        13
#define ASN_TIME_ERR        14
#define ASN_CODING_ERR      15
#define ASN_NULL_PTR        16
#define ASN_NONE_ERR        17
#define ASN_UNDEF_VALUE     18
#define ASN_NO_CHOICE_ERR   19
#define ASN_MASK_ERR        20
#define ASN_DEFINED_ERR     21
#define ASN_LENGTH_ERR      22
#define ASN_FILE_SIZE_ERR   23
#define ASN_CONSTRAINT_ERR  24
#define ASN_RECURSION_ERR   25
#define ASN_ENUM_ERR        26
#define ASN_FILE_ERR        27

struct casn
    {
    long tag;
    uchar *startp;  
    ulong lth;
    ushort type, level;
    ushort flags;
    short min;
    ulong max;
    struct casn *ptr;
#ifdef CONSTRAINTS
    uchar *constraint;
#endif
    };

struct casn_err_struct
    {
    int errnum;
    char *asn_map_string;
    struct casn *casnp;
    };

extern struct casn_err_struct casn_err_struct;

int copy_casn(struct casn *, struct casn *),
    decode_casn(struct casn *casnp, uchar *from),
    decode_casn_lth(struct casn *, uchar *, int),
    diff_casn(struct casn *, struct casn *),
    diff_casn_num(struct casn *casnp, long val),
    diff_casn_time(struct casn *casnp1, struct casn *casnp2),
    diff_objid(struct casn *fr_casnp, char *objidp),
    dump_casn(struct casn *, char *),
    dump_size(struct casn *),
    eject_casn(struct casn *, int),
    encodesize_casn(struct casn *, uchar **),
    encode_casn(struct casn *, uchar *),
    get_casn_file(struct casn *casnp, char *, int),
    num_items(struct casn *casnp),
    put_casn_file(struct casn *casnp, char *, int),
    readvsize_casn(struct casn *, uchar **),
    readvsize_objid(struct casn *, char **),
    read_casn(struct casn *, uchar *),
    read_casn_bit(struct casn *),
    read_casn_bits(struct casn *casnp, uchar *to, int *shift),
    read_casn_double(struct casn *casnp, double *val),
    read_casn_num(struct casn *, long *),
    read_casn_time(struct casn *, ulong *),
    read_objid(struct casn *, char *),
    remove_casn(struct casn *casnp, int num),
    size_casn(struct casn *),
    tag_casn(struct casn *),
    vsize_casn(struct casn *),
    vsize_casn_bits(struct casn *casnp),
    vsize_objid(struct casn *casnp), 
    write_casn(struct casn *, uchar *, int),
    _write_casn(struct casn *casnp, uchar *c, int lth),
    _write_casn_num(struct casn *casnp, long),
    write_casn_bit(struct casn *, int),
    write_casn_bits(struct casn *casnp, uchar *from, int lth, int shift),
    write_casn_double(struct casn *casnp, double val, int base),
    write_casn_num(struct casn *, long),
    write_casn_time(struct casn *, ulong),
    write_objid(struct casn *, char *),
    _write_objid(struct casn *, char *);  // for use by constructors only

void delete_casn(struct casn *),
    clear_casn(struct casn *),
    simple_constructor(struct casn *, ushort level, int type),
    tagged_constructor(struct casn *, ushort level, int type, int tag);

struct casn *dup_casn(struct casn *casnp),
            *index_casn(struct casn *casnp, int num),
            *inject_casn(struct casn *, int),
            *insert_casn(struct casn *casnp, int num),
            *member_casn(struct casn *casnp, int num),
            *next_of(struct casn *casnp);

#ifndef DEBUG
#define dbcalloc calloc
#define dbfree free
#else
uchar *dbcalloc(int, int);
#endif
    // for reals
#define ASN_PLUS_INFINITY  0x40
#define ASN_MINUS_INFINITY 0x41
#define ISO6093NR1          10
#define ISO6093NR2          12
#define ISO6093NR3          14

#endif  // _casn_h

