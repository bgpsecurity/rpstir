#ifndef LIB_CASN_CASN_PRIVATE_H
#define LIB_CASN_CASN_PRIVATE_H

#include <stdint.h>

struct casn;

void
_clear_casn(
    struct casn *,
    unsigned short);

struct casn *
_find_chosen(
    struct casn *casnp);

struct casn *
_dup_casn(
    struct casn *casnp);

struct casn *
_find_filled(
    struct casn *casnp);

struct casn *
_find_filled_or_chosen(
    struct casn *casnp,
    int *errp);

struct casn *
_find_tag(
    struct casn *casnp,
    unsigned long tag);

struct casn *
_go_up(
    struct casn *casnp);

struct casn *
_skip_casn(
    struct casn *casnp,
    int num);

int
_casn_obj_err(
    struct casn *,
    int);

int
_calc_lth_lth(
    int);

int
_check_filled(
    struct casn *,
    int);

int
_clear_error(
    struct casn *);

int
_encode_tag_lth(
    unsigned char *to,
    struct casn **casnpp);

int
_fill_upward(
    struct casn *casnp,
    int val);

int
_utctime_to_ulong(
    int64_t *valp,
    char *fromp,
    int lth);

int
_gentime_to_ulong(
    int64_t *valp,
    char *fromp,
    int lth);

int
_dump_tag(
    int tag,
    char *to,
    int offset,
    unsigned short flags,
    int mode);

int
_calc_lth(
    unsigned char **cpp,
    unsigned char ftag);

int
_check_enum(
    struct casn **casnpp);

int
_table_op(
    struct casn *casnp);

int
_write_casn(
    struct casn *casnp,
    unsigned char *c,
    int lth);

int
_write_enum(
    struct casn *casnp);

int
_write_objid(
    struct casn *casnp,
    const char *from);

long
_get_tag(
    unsigned char **tagpp);

void *
_free_it(
    void *);

int
set_asn_lth(
    unsigned char *,
    unsigned char *);

// modes for encode & read
#define ASN_READ 1

int
_readsize_objid(
    struct casn *casnp,
    char *to,
    int mode);

char *
_putd(
    char *to,
    long val);

#endif /* LIB_CASN_CASN_PRIVATE_H */
