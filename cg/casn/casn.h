/* sfcsid[] = "@(#)casn.h 830P" */
/*****************************************************************************
File:     casn.h
Contents: Basic definitions
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

 ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 3.0-beta
 * 
 * COMMERCIAL COMPUTER SOFTWARE RESTRICTED RIGHTS (JUNE 1987)
 * US government users are permitted restricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 2004-2010.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK *****
*****************************************************************************/

#ifndef _casn_h
#define _casn_h
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include "asn.h"
#include "asn_flags.h"
#include "asn_error.h"

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
    ulong num_items;
    struct casn *lastp;
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
    eject_all_casn(struct casn *),
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
    read_casn_time(struct casn *, int64_t *),
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
    write_casn_time(struct casn *, int64_t),
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
#define ASN_UNDEFINED_LTH 0x7FFFFFFF
    // for reals
#define ASN_PLUS_INFINITY  0x40
#define ASN_MINUS_INFINITY 0x41
#define ISO6093NR1          10
#define ISO6093NR2          12
#define ISO6093NR3          14

#endif  // _casn_h

