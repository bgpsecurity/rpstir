/*****************************************************************************
File:     casn.h
Contents: Basic definitions
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

*****************************************************************************/

#ifndef _casn_h
#define _casn_h
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include "casn/asn.h"
#include "casn/asn_flags.h"
#include "casn/asn_error.h"

struct casn {
    long tag;
    uchar *startp;
    ulong lth;
    ushort type,
        level;
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

struct casn_err_struct {
    int errnum;
    char *asn_map_string;
    struct casn *casnp;
};

extern struct casn_err_struct casn_err_struct;

struct oidtable {
    char *oid;
    char *label;
};

int
copy_casn(
    struct casn *,
    struct casn *);

int
decode_casn(
    struct casn *casnp,
    uchar * from);

int
decode_casn_lth(
    struct casn *,
    uchar *,
    int);

int
diff_casn(
    struct casn *,
    struct casn *);             // can return -2 (error)!

int
diff_casn_num(
    struct casn *casnp,
    long val);                  // can return -2 (error)!

int
diff_casn_time(
    struct casn *casnp1,
    struct casn *casnp2);       // can return -2 (error)!

int
diff_objid(
    struct casn *fr_casnp,
    const char *objidp);

int
dump_casn(
    struct casn *,
    char *);

int
dump_size(
    struct casn *),
    eject_casn(
    struct casn *,
    int);

int
eject_all_casn(
    struct casn *),
    encodesize_casn(
    struct casn *,
    uchar **);

int
encode_casn(
    struct casn *,
    uchar *);

int
get_casn_file(
    struct casn *casnp,
    const char *,
    int);

int
num_items(
    struct casn *casnp);

int
put_casn_file(
    struct casn *casnp,
    char *,
    int);

int
readvsize_casn(
    struct casn *,
    uchar **);

int
readvsize_objid(
    struct casn *,
    char **);

int
read_casn(
    struct casn *,
    uchar *);

int
read_casn_bit(
    struct casn *);

int
read_casn_bits(
    struct casn *casnp,
    uchar *to,
    int *shift);

int
read_casn_double(
    struct casn *casnp,
    double *val);

int
read_casn_num(
    struct casn *,
    long *);

int
read_casn_num_max(
    struct casn *,
    intmax_t *);

int
read_casn_time(
    struct casn *,
    int64_t *);

int
read_objid(
    struct casn *,
    char *);

int
size_casn(
    struct casn *);

int
tag_casn(
    struct casn *);

int
vsize_casn(
    struct casn *);

int
vsize_casn_bits(
    struct casn *casnp);

int
vsize_objid(
    struct casn *casnp);

int
write_casn(
    struct casn *,
    uchar *,
    int);

int
_write_casn(
    struct casn *casnp,
    uchar *c,
    int lth);

int
_write_casn_num(
    struct casn *casnp,
    long);

int
write_casn_bit(
    struct casn *,
    int);

int
write_casn_bits(
    struct casn *casnp,
    uchar *from,
    int lth,
    int shift);

int
write_casn_double(
    struct casn *casnp,
    double val,
    int base);

int
write_casn_num(
    struct casn *,
    long);

int
write_casn_time(
    struct casn *,
    int64_t);

int
write_objid(
    struct casn *,
    const char *);

int
_write_objid(
    struct casn *,
    const char *);                    // for use by constructors only

int
cf_oid(
    char *curr_oid,
    char *test_oid);

int
adjustTime(
    struct casn *timep,
    long basetime,
    char *deltap);

void
delete_casn(
    struct casn *);

void
clear_casn(
    struct casn *);

void
simple_constructor(
    struct casn *,
    ushort level,
    int type);

void
tagged_constructor(
    struct casn *,
    ushort level,
    int type,
    int tag);

void
load_oidtable(
    char *name);

struct casn *
dup_casn(
    struct casn *casnp);

struct casn *
inject_casn(
    struct casn *,
    int);

struct casn *
member_casn(
    struct casn *casnp,
    int num);

struct casn *
next_of(
    struct casn *casnp);

char *
find_label(
    char *oidp,
    int *diffp,
    struct oidtable *oidtable,
    int oidtable_size);

#ifndef DEBUG
#define dbcalloc calloc
#define dbfree free
#else
uchar *
dbcalloc(
    int,
    int);
#endif
#define ASN_UNDEFINED_LTH 0x7FFFFFFF
    // for reals
#define ASN_PLUS_INFINITY  0x40
#define ASN_MINUS_INFINITY 0x41
#define ISO6093NR1          10
#define ISO6093NR2          12
#define ISO6093NR3          14

#endif                          // _casn_h
