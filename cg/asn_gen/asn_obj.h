/* $Id$ */
/* Sep  7 2004 805U  */
/* Sep  7 2004 GARDINER added encodesize and readvsize methods */
/* May 26 2004 768U  */
/* May 26 2004 GARDINER moved BOOL flags to asn_flags.h */
/* May 25 2004 765U  */
/* May 25 2004 GARDINER moved flags to asn_flags.h */
/* Mar  3 2004 740U  */
/* Mar  3 2004 GARDINER added ASN_RANGE_FLAG for asn_cgen */
/* Jan  6 2004 737U  */
/* Jan  6 2004 GARDINER changed to handle [0] EXPLICIT OCTET STRING DEFINED BY */
/* Jun 10 2003 621U  */
/* Jun 10 2003 GARDINER more fixes for sub-objid */
/* Jun  4 2003 619U  */
/* Jun  4 2003 GARDINER added AsnObjectIdentifier::_set_sub_val */
/* Jan 24 2003 613U  */
/* Jan 24 2003 GARDINER added AsnBitString.read with no shift */
/* Jan 23 2003 612U  */
/* Jan 23 2003 GARDINER fixed for exported BIT STRING */
/* Jun  5 2002 604U  */
/* Jun  5 2002 GARDINER made AsnNumeric set _default to 0 */
/* Dec  7 2001 599U  */
/* Dec  7 2001 GARDINER moved _default to AsnNumeric */
/* Aug  6 2001 589U  */
/* Aug  6 2001 GARDINER added _default to AsnEnumerated */
/* Apr  2 2001 572U  */
/* Apr  2 2001 GARDINER cut out includes when cross-compiling for SA+ */
/* Jan 19 2001 560U  */
/* Jan 19 2001 GARDINER put assignment of UTF8 back in; UTF8 can't have nulls */
/* Jan 19 2001 559U  */
/* Jan 19 2001 GARDINER removed assignment reference for UTF8 class; can't do; it has nulls */
/* Dec 20 2000 554U  */
/* Dec 20 2000 GARDINER added unsigned long to comparisons, assignments & en/decoding */
/* Dec  4 2000 552U  */
/* Dec  4 2000 GARDINER added include of asn_timedefs.h */
/* Nov  8 2000 547U  */
/* Nov  8 2000 GARDINER added operators for AsnObjectIdentifier class */
/* Mar 20 1998 492U  */
/* Mar 20 1998 GARDINER changed */
/* Mar  2 1998 490U  */
/* Mar  2 1998 GARDINER added AsnTime members that should have been inherited */
/* Feb 12 1998 487U  */
/* Feb 12 1998 GARDINER added AsnTime and comparison functions */
/* Feb 11 1998 486U  */
/* Feb 11 1998 GARDINER year 2000 fixes */
/* Jan 21 1998 482U  */
/* Jan 21 1998 GARDINER changed enum_read to enum_readsize */
/* Jan 14 1998 479U  */
/* Jan 14 1998 GARDINER provided for getting less than all of a file */
/* Nov 10 1997 471U  */
/* Nov 10 1997 GARDINER portability fixes */
/* Oct 29 1997 468U  */
/* Oct 29 1997 GARDINER added typing for portability */
/* Oct 21 1997 467U  */
/* Oct 21 1997 GARDINER moved std includes here from includes.h */
/* Oct 16 1997 465U  */
/* Oct 16 1997 GARDINER added write(const char *) */
/* Sep 16 1997 458U  */
/* Sep 16 1997 GARDINER fixed named bit strings */
/* May 15 1997 438U  */
/* May 15 1997 GARDINER fixed map string stuffing for bigger arrays */
/* May  5 1997 435U  */
/* May  5 1997 GARDINER removed unnecessary definition of map function */
/* Dec  2 1996 407U  */
/* Dec  2 1996 GARDINER added comments for BOOL_DEF* */
/* Nov 22 1996 400U  */
/* Nov 22 1996 GARDINER added get/put_asn_time to class AsnObj */
/* May 29 1996 371U  */
/* May 29 1996 GARDINER added BOOL_DEFINED_VAL & boolean constraint() */
/* Apr  9 1996 363U  */
/* Apr  9 1996 GARDINER added asn_constraint_ptr */
/* Apr  5 1996 360U  */
/* Apr  5 1996 GARDINER added operators to AsnNumericArray */
/* Apr  4 1996 358U  */
/* Apr  4 1996 GARDINER changed num_diff to _num_diff */
/* Mar 29 1996 356U  */
/* Mar 29 1996 GARDINER added _get_sub_tag, _default in AsnInteger*/
/* Mar 22 1996 352U  */
/* Mar 22 1996 GARDINER DOS-proofed */
/* Mar 11 1996 348U  */
/* Mar 11 1996 GARDINER fixed comparison of CHOICE */
/* Mar  4 1996 347U  */
/* Mar  4 1996 GARDINER added comparison operators for AsnOIDTableObj */
/* Feb 21 1996 336U  */
/* Feb 21 1996 GARDINER added <, <=, >=, > operators */
/* Feb  9 1996 331U  */
/* Feb  9 1996 GARDINER added AsnNumTableObj and AsnOIDTableObj */
/* Feb  2 1996 329U  */
/* Feb  2 1996 GARDINER added _clear_error(); altered check_efilled() */
/* Jan 25 1996 324U  */
/* Jan 25 1996 GARDINER added constraint checking; improved 'const's */
/* Jan 10 1996 323U  */
/* Jan 10 1996 GARDINER changed SUB_EXPORT_FLAG to CONSTRAINT_FLAG */
/* Jan  5 1996 320U  */
/* Jan  5 1996 GARDINER fixes for new asn_obj_err() */
/* Jan  4 1996 319U  */
/* Jan  4 1996 GARDINER made asn_error() a member function */
/* Nov 27 1995 316U  */
/* Nov 27 1995 GARDINER removed 'float' functions */
/* Nov 20 1995 315U  */
/* Nov 20 1995 GARDINER revised class names of arrays */
/* Nov 17 1995 314U  */
/* Nov 17 1995 GARDINER moved virtual _dup() to AsnObj; created AsnSetArray */
/* Nov 15 1995 311U  */
/* Nov 15 1995 GARDINER added AsnSet as friend of AsnObj */
/* Nov 15 1995 310U  */
/* Nov 15 1995 GARDINER added AsnReal */
/* Nov  3 1995 305U  */
/* Nov  3 1995 GARDINER fixed BitStrings */
/* Nov  1 1995 304U  */
/* Nov  1 1995 GARDINER removed _bitmask stuff */
/* Oct 31 1995 303U  */
/* Oct 31 1995 GARDINER protected members; removed _mask; changed _type */
/* Oct 31 1995    added new class AsnBit */
/* Oct  2 1995 289U  */
/* Oct  2 1995 GARDINER moved masks from C++ area to C area */
/* Oct  2 1995 288U  */
/* Oct  2 1995 GARDINER added IA5 mask */
/* Sep 25 1995 282U  */
/* Sep 25 1995 GARDINER added assignment, comparison and conversion operators */
/* Sep 11 1995 278U  */
/* Sep 11 1995 GARDINER added UcharArray::copy() */
/* Sep  8 1995 276U  */
/* Sep  8 1995 GARDINER added set_definees() as a member function */
/* Sep  5 1995 273U  */
/* Sep  5 1995 GARDINER changed to keep SET items in order in chain, introducing _relinksp */
/* Aug 31 1995 271U  */
/* Aug 31 1995 GARDINER made _dup & _point virtual functions */
/* Aug 30 1995 269U  */
/* Aug 30 1995 GARDINER fixed for AsnPtrArray */
/* Aug 22 1995 261U  */
/* Aug 22 1995 GARDINER removed ASN_ANY_FLAG */
/* Aug  4 1995 257U  */
/* Aug  4 1995 GARDINER added member functions */
/* Jul 11 1995 245U  */
/* Jul 11 1995 GARDINER fixed table stuff */
/* Jul 10 1995 242U  */
/* Jul 10 1995 GARDINER added set_definees() */
/* Jul  5 1995 240U  */
/* Jul  5 1995 GARDINER added decode(uchar *, int) */
/* Jun 30 1995 GARDINER compressed batches   1 through 240 on Feb 12 1996 */
/*****************************************************************************
File:     asn_obj.h
Contents: Header file for the ASN_GEN program and the basic library
        functions.
System:   ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

COPYRIGHT 1995 BBN Systems and Technologies, A Division of BBN Inc.
150 CambridgePark Drive
Cambridge, Ma. 02140
617-873-4000
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
#include "asn_error.h"
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

#ifdef __cplusplus

  /* values for mode in encodesize() and readsize() */
  /* zero is sizing or vsizing */
#define ASN_READING 1          /* reading or encoding */
#define ASN_RE_SIZING 2        /* re_sizing or re_vsizing */
#define ASN_RE_READING 3       /* re-reading or re_encoding */

class AsnObj;

class UcharArray
    {
  public:
    UcharArray(long);
    UcharArray(const uchar *, long);
    ~UcharArray(){ delete [] ua;}
    long size() { return siz; }
    uchar& operator[](long index) { return ua[index]; }
    long append(const uchar *, long);
    long fill(const uchar *, long);
    void copy(AsnObj *) const;
    int diff(const AsnObj *) const;
    int diff(const char *) const;
  protected:
    long siz;
    uchar *ua;
  private:
    friend class AsnObj;
    friend class AsnTime;
    };

class AsnPtr;

class AsnObj
    {
  public:
    AsnObj();
    virtual ~AsnObj();
    void clear();
    void asn_error(const int, const char *) const;
    int asn_obj_err(const int) const;
    virtual int constraint() const;
    long copy(AsnObj *) const;
    long decode(const uchar *);
    long decode(const uchar *, long);
    int diff(const AsnObj *) const;
    long dump(char *) const;
    long dump_size() const;
    long encode(uchar *) const;
    long encodesize(uchar **) const;
    long get_file(const char *);
    long get_file(int);
    long get_file(const char *, int *);
    long get_file(int, int *);
    long _get_sub_tag() const { return _tag; } ;
    long put_file(const char *) const;
    long put_file(int) const;
    long read(uchar *) const;
    long readvsize(uchar **) const;
    int read(long *) const;
    int read(ulong *) const;
    long re_encode(uchar *) const;
    long re_read(uchar *) const;
    long re_size() const;
    long re_vsize() const;
    long size() const;
    int tag(ulong *) const;
    long vsize() const;
    long write(const uchar *, const ulong );
    long write(const char *);
    int write(const long);
    int write(const ulong);
    void operator=(const AsnObj &);
    int operator!=(const AsnObj &) const;
    int operator==(const AsnObj &) const;
    int operator<=(const AsnObj &) const;
    int operator>=(const AsnObj &) const;
    int operator<(const AsnObj &) const;
    int operator>(const AsnObj &) const;
    void map() const;
  protected:
    AsnObj *_next, *_sub, *_supra;
    ulong _tag;
    ushort _flags, _type;
    long _min, _max;
    UcharArray *_valp;
    long _append(const uchar *, ulong);
    void _boundset(AsnObj *, long, long);
    const AsnObj *_check_choice() const;
    AsnObj *_check_defined();
    int _check_of();
    int _check_efilled(int) const;
    int _check_vfilled() const;
    int _check_filled() const;
    int _check_mask(const uchar *from, long lth);
    void _clear(int);
    void _clear_error() const;
    int _compare(const AsnObj &) const;
    int _compare(const uchar *, long);
    long _csize(long) const;
    long _csize(const uchar *, long) const;
    int _dump_tag(char *, ulong, int, ushort, int) const;
    long _dumpsize(char *, int, int) const;
    long _dumpread(char *, int, int) const;
    virtual AsnObj *_dup();         // makes new instance of object.
    long _encodesize(uchar *, int) const;
    int _encode_lth(uchar *, ulong) const;
    int _encode_tag(uchar *, ulong)const;
    int _enum_readsize(uchar *, int) const;
    void _fill_upward(int);
    long _find_lth(const uchar *);
    ulong _get_asn_time(const char *from, int lth) const;
    AsnObj *_go_down() { return _sub; }
    AsnObj *_go_up() { return _supra; }
    AsnObj *_go_next() { return _next; }
    long _insert();
    AsnObj *_index_op(long) const;
    int _is_default() const;
    long _match(const uchar *, const uchar *);
    int _map(char **, int, int) const;
    void _multi_stuff(int, const AsnObj *) const;
    int _put_asn_time(char *to, ulong time) const;
    long _read(uchar *) const;
    int _read_empty(int, int) const;
    long _readsize(uchar *, int) const;
    long _remove();
    void _setup(AsnObj *, AsnObj *, ushort, ulong);
    void _set_type(AsnObj *, ulong);
    int _set_asn_lth(uchar *from, uchar *to, int mode) const;
    void _set_pointers(AsnObj *);   // called by all _dup()
    void _set_sub_flag(AsnObj *, ushort);
    void _set_sub_val(AsnObj *, const uchar *, long);
    void _set_tag(AsnObj *, ulong);
    void _set_type_tag(AsnObj *, ulong);
    void _set_supra(AsnObj *);
    AsnObj *_tag_match(ulong, int *);
    AsnObj *_tag_scan(AsnObj **, const uchar *, int, int *);
    AsnObj *_tag_search(ulong, int *);
    long _write(const uchar *, ulong );
  private:
    AsnObj(const AsnObj &);
    friend class UcharArray;
    friend class AsnTableObj;
    friend class AsnBoolean;
    friend class AsnBitString;
    friend class AsnReal;
    friend class AsnSet;
    friend class AsnOf;
    friend class AsnPtr;
    friend class AsnArray;
    friend class AsnNumericArray;
    friend class AsnArrayOfOfs;
    friend class AsnArrayOfPtrs;
    friend class AsnArrayOfPtrsOf;
    friend class  AsnChoice;
    };

extern const AsnObj *asn_err_ptr;   /* must be mentioned after class AsnObj */

class AsnTableObj : public AsnObj
    {
  public:
    UcharArray *wherep;
    void operator=(const AsnTableObj &);
    int operator==(const AsnTableObj &) const;
    int operator!=(const AsnTableObj &) const;
    AsnTableObj();
    ~AsnTableObj();
  protected:
    int _set_definees(int);
    AsnObj *AsnTableObj::_setup_table(AsnObj *, char *, int, int);
    friend class AsnObj;
    };

class AsnNumTableObj : public AsnTableObj
    {
  public:
    int operator!=(const long) const;
    int operator==(const long) const;
    int operator<=(const long) const;
    int operator>=(const long) const;
    int operator<(const long) const;
    int operator>(const long) const;
    int _compare(const long) const;
    operator long () const;
    int operator!=(const ulong) const;
    int operator==(const ulong) const;
    int operator<=(const ulong) const;
    int operator>=(const ulong) const;
    int operator<(const ulong) const;
    int operator>(const ulong) const;
    int _compare(const ulong) const;
    operator ulong () const;
    };

class AsnOIDTableObj : public AsnTableObj
    {
  public:
    int operator!=(const char *) const;
    int operator==(const char *) const;
    int operator<=(const char *) const;
    int operator>=(const char *) const;
    int operator<(const char *) const;
    int operator>(const char *) const;
    int operator<=(const AsnOIDTableObj &) const;
    int operator>=(const AsnOIDTableObj &) const;
    int operator<(const AsnOIDTableObj &) const;
    int operator>(const AsnOIDTableObj &) const;
    int _compare(const AsnOIDTableObj &) const;
    };

class AsnAny : public AsnObj
    {
  public:
    AsnAny();
    };

class AsnNumeric : public AsnObj
    {
  public:
    long _default;
    AsnNumeric();
    void _set_def(long val) { _default = val; };
    int operator!=(const long) const;
    int operator==(const long) const;
    int operator<=(const long) const;
    int operator>=(const long) const;
    int operator<(const long) const;
    int operator>(const long) const;
    int operator!=(const ulong) const;
    int operator==(const ulong) const;
    int operator<=(const ulong) const;
    int operator>=(const ulong) const;
    int operator<(const ulong) const;
    int operator>(const ulong) const;
    int operator<=(const AsnNumeric &) const;
    int operator>=(const AsnNumeric &) const;
    int operator<(const AsnNumeric &) const;
    int operator>(const AsnNumeric &) const;
    int _compare(const AsnNumeric &) const;
    void operator=(const long);
    void operator=(const ulong);
    operator long () const;
    operator ulong () const;
    };

class AsnBoolean : public AsnNumeric
    {
  public:
    void operator=(const long);
    void operator=(const ulong);
    int constraint() const;
    AsnBoolean();
    };

class AsnInteger : public AsnNumeric
    {
  public:
    void operator=(const long);
    void operator=(const ulong);
    int _num_diff(const uchar *, const long) const;
    AsnInteger();
    };

class AsnBit : public AsnObj
    {
  public:
    operator long () const;
    int operator!=(const long) const;
    int operator==(const long) const;
    void operator=(const long);
    };

class AsnBitString : public AsnObj
    {
  public:
    long read(uchar *, int *) const;
    long read(uchar *, uchar *) const;
    long vsize() const;
    int _compare(const AsnBitString &) const;
    long write(const uchar *, ulong, int);
    AsnBitString();
  protected:
    long _readsize(uchar *, int *, int) const;
    };

class AsnString : public AsnObj
    {
  public:
    int operator!=(const char *) const;
    int operator==(const char *) const;
    int _compare(const AsnString &) const;
    };

class AsnOctetString : public AsnString
    {
  public:
    void operator=(const char *);
    AsnOctetString();
    };

class AsnNull : public AsnObj
    {
  public:
    AsnNull();
    };

class AsnObjectIdentifier : public AsnObj
    {
  public:
    long read(uchar *) const;
    long vsize() const;
    long write(const char *, ulong);
    long write(const char *);
    long _readsize(uchar *, int) const;
    void operator=(const char *);
    int operator!=(const char *) const;
    int operator==(const char *) const;
    int operator<=(const char *) const;
    int operator>=(const char *) const;
    int operator<(const char *) const;
    int operator>(const char *) const;
    int operator==(const AsnObjectIdentifier &) const;
    int operator!=(const AsnObjectIdentifier &) const;
    int operator<=(const AsnObjectIdentifier &) const;
    int operator>=(const AsnObjectIdentifier &) const;
    int operator<(const AsnObjectIdentifier &) const;
    int operator>(const AsnObjectIdentifier &) const;
    int _compare(const AsnObjectIdentifier &) const;
    AsnObjectIdentifier();
    };

#define ASN_PLUS_INFINITY  0x40
#define ASN_MINUS_INFINITY 0x41
#define ISO6093NR1          10
#define ISO6093NR2          12
#define ISO6093NR3          14

class AsnReal : public AsnObj
    {
  public:
    int read(double *) const;
    int write(const double, int base);
    int _compare(const AsnReal &) const;
    AsnReal();
    };

class AsnEnumerated : public AsnNumeric
    {
  public:
    void operator=(const long);
    void operator=(const ulong);
    AsnEnumerated();
    };

class AsnUTF8String : public AsnString
    {
  public:
    void operator=(const char *);
    AsnUTF8String();
    };

class AsnNumericString : public AsnString
    {
  public:
    void operator=(const char *);
    AsnNumericString();
    };

class AsnPrintableString : public AsnString
    {
  public:
    void operator=(const char *);
    AsnPrintableString();
    };

class AsnTeletexString : public AsnString
    {
  public:
    void operator=(const char *);
    AsnTeletexString();
    };

class AsnVideotexString : public AsnString
    {
  public:
    void operator=(const char *);
    AsnVideotexString();
    };

class AsnIA5String : public AsnString
    {
  public:
    void operator=(const char *);
    AsnIA5String();
    };

class AsnTime : public AsnObj
    {
  public:
    int read(ulong *) const;
    long read(uchar *val) { return ((AsnObj *)this)->read(val); };
    int write(ulong);
    long write(const char *val) { return ((AsnObj *)this)->write(val); };
    long write(const uchar *val, const ulong lth)
        { return ((AsnObj *)this)->write(val, lth); };
    int operator!=(const ulong) const;
    int operator==(const ulong) const;
    int operator<=(const ulong) const;
    int operator>=(const ulong) const;
    int operator<(const ulong) const;
    int operator>(const ulong) const;
    int operator<=(const AsnTime &) const;
    int operator>=(const AsnTime &) const;
    int operator<(const AsnTime &) const;
    int operator>(const AsnTime &) const;
    int _compare(const AsnTime &) const;
    void operator=(const ulong);
    operator ulong () const;
    };


class AsnUTCTime : public AsnTime
    {
  public:
    void operator=(const ulong val);
    AsnUTCTime();
    };

class AsnGeneralizedTime : public AsnTime
    {
  public:
    void operator=(const ulong val);
    AsnGeneralizedTime();
    };

class AsnGraphicString : public AsnString
    {
  public:
    void operator=(const char *);
    AsnGraphicString();
    };

class AsnVisibleString : public AsnString
    {
  public:
    void operator=(const char *);
    AsnVisibleString();
    };

class AsnGeneralString : public AsnString
    {
  public:
    void operator=(const char *);
    AsnGeneralString();
    };

class AsnUniversalString : public AsnString
    {
  public:
    void operator=(const char *);
    AsnUniversalString();
    };

class AsnBMPString : public AsnString
    {
  public:
    void operator=(const char *);
    AsnBMPString();
    };


class AsnSequence : public AsnObj
    {
  public:
    void operator=(const AsnSequence &);
    int operator!=(const AsnSequence &) const;
    int operator==(const AsnSequence &) const;
    AsnSequence();
    };

class AsnLink
    {
  public:
    AsnLink *_next;
    AsnObj *objp;
    AsnLink();
    ~AsnLink();
    };

class AsnSet : public AsnObj
    {
  public:
    AsnLink *_relinksp;
    void operator=(const AsnSet &);
    int operator!=(const AsnSet &) const;
    int operator==(const AsnSet &) const;
    void add_link(AsnObj *);
    AsnSet();
    ~AsnSet();
    };

class AsnArrayOfSets : public AsnSet
    {
  public:
    long insert();
    long remove();
    AsnArrayOfSets& operator[](long) const;
    };

class AsnOf : public AsnObj             /* only heirs used */
    {
  public:
    long numitems() const;
    void operator=(const AsnOf &);
    int operator!=(const AsnOf &) const;
    int operator==(const AsnOf &) const;
    AsnOf();
    };

class AsnSequenceOf : public AsnOf
    {
  public:
    AsnSequenceOf();
    };

class AsnSetOf : public AsnOf
    {
  public:
    AsnSetOf();
    };

class AsnPtr : public AsnObj
    {
  public:
    AsnObj *_ptr;
    virtual void _point();      // makes new pointed-to object
    void _set_ptr();       // called by all _point()
    void operator=(AsnObj *);
    void operator=(const AsnPtr &);
    int operator==(const AsnPtr &) const;
    int operator!=(const AsnPtr &) const;
    AsnPtr();
    ~AsnPtr();
    };

class AsnArray : public AsnObj  /* member of an array, not set/sequence of */
    {
  public:
    long insert();
    long remove();
    AsnArray& operator[](long) const;
    ~AsnArray();
    };

class AsnNumericArray : public AsnArray
    {
  public:
    long _default;
    void _set_def(long val) { _default = val; };
    int operator!=(const long) const;
    int operator==(const long) const;
    int operator<=(const long) const;
    int operator>=(const long) const;
    int operator<(const long) const;
    int operator>(const long) const;
    int operator!=(const ulong) const;
    int operator==(const ulong) const;
    int operator<=(const ulong) const;
    int operator>=(const ulong) const;
    int operator<(const ulong) const;
    int operator>(const ulong) const;
    int operator<=(const AsnNumericArray &) const;
    int operator>=(const AsnNumericArray &) const;
    int operator<(const AsnNumericArray &) const;
    int operator>(const AsnNumericArray &) const;
    int _compare(const AsnNumericArray &) const;
    void operator=(const long);
    void operator=(const ulong);
    operator long () const;
    operator ulong () const;
    };

class AsnStringArray : public AsnArray
    {
  public:
    void operator=(const char *);
    };

class AsnBitStringArray : public AsnArray
    {
  public:
    void operator=(const char *);
    long write(const uchar *, ulong, int);
    long read(uchar *, int *);
    long read(uchar *, uchar *);
    long vsize() const;
    };

class AsnArrayOfOfs : public AsnArray  /* member of an array AND a set/seq of */
    {                               /* only its heirs are used */
  public:
    long numitems() const;
    AsnArrayOfOfs();
    };

class AsnArrayOfSequencesOf : public AsnArrayOfOfs
    {
  public:
    AsnArrayOfSequencesOf();
    };

class AsnArrayOfSetsOf : public AsnArrayOfOfs
    {
  public:
    AsnArrayOfSetsOf();
    };

class AsnArrayOfPtrs : public AsnPtr /* member of an array AND is a ptr */
    {                               /* only its heirs are used  */
  public:
    long insert();
    long remove();
    AsnArrayOfPtrs *index_op(long);
    AsnArrayOfPtrs();
    ~AsnArrayOfPtrs();
    };

class AsnArrayOfPtrsOf : public AsnArrayOfPtrs  // member of an array AND
    {                                           // is a ptr to SET/SEQ OF
  public:
    long numitems() const;
    };


class AsnArrayOfPtrSequenceOf : public AsnArrayOfPtrsOf
    {
  public:
    AsnArrayOfPtrSequenceOf();
    };

class AsnArrayOfPtrSetOf : public AsnArrayOfPtrsOf
    {
  public:
    AsnArrayOfPtrSetOf();
    };

class AsnChoice : public AsnObj
    {
  public:
    void operator=(const AsnChoice &);
    int operator!=(const AsnChoice &) const;
    int operator==(const AsnChoice &) const;
    AsnChoice();
    };

class AsnNone : public AsnObj
    {
  public:
    AsnNone();
    };

class AsnNotAsn1 : public AsnObj
    {
  public:
    AsnNotAsn1();
    };

#endif
#endif /* _ASN_OBJ_H */
