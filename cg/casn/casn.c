/*****************************************************************************
File:     casn.c
Contents: Basic functions for ASN.1 objects.
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

COPYRIGHT 2004 BBN Systems and Technologies
10 Moulton St.
Cambridge, Ma. 02138
617-873-3000
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

char casn_sfcsid[] = "@(#)casn.c 871P";
#include "casn.h"
#include <stdio.h>
#include "logutils.h"

#define ASN_READ 1          // modes for encode & read

extern int _utctime_to_ulong(ulong *valp, char *fromp, int lth);
extern int _gentime_to_ulong(ulong *valp, char *fromp, int lth);
extern int _dump_tag(int tag, char *to, int offset, ushort flags,
    int mode);

static struct casn_errors
    {
    int num;
    char *msg;
    } casn_errors[] =
    {
    { ASN_MATCH_ERR,      "Stream doesn't match object" },
    { ASN_MEM_ERR,        "Error getting memory"},
    { ASN_GEN_ERR,        "Error in casn_gen's code"},
    { ASN_CHOICE_ERR,     "Can't write to a CHOICE"},
    { ASN_OF_ERR,         "Tags not consistent in SET/SEQ OF"},
    { ASN_MANDATORY_ERR,  "Mandatory field is not filled in" },
    { ASN_NOT_OF_ERR,     "Not a SET/SEQ OF"},
    { ASN_OF_BOUNDS_ERR,  "Out of bounds in SET/SEQ OF"},
    { ASN_EMPTY_ERR,      "Source is empty"},
    { ASN_DEFINER_ERR,    "Definer not in table"},
    { ASN_NO_DEF_ERR,     "DEFINED BY not defined yet"},
    { ASN_BOUNDS_ERR,     "Size out of bounds"},
    { ASN_TYPE_ERR,       "Invalid operation for this type"},
    { ASN_TIME_ERR,       "Invalid time field"},
    { ASN_CODING_ERR,     "Improper ASN.1 string"},
    { ASN_NULL_PTR,       "Null pointer passed to member function" },
    { ASN_NONE_ERR,       "Can't write to a NONE"},
    { ASN_UNDEF_VALUE,    "Trying to write an undefined value" }, // reals only
    { ASN_NO_CHOICE_ERR,  "Character string not valid for any of CHOICE" },
    { ASN_MASK_ERR,       "Invalid character at [-(value returned)]"},
    { ASN_DEFINED_ERR,    "Error trying to find DEFINED BY" },
    { ASN_LENGTH_ERR,     "Invalid length field" },
    { ASN_FILE_SIZE_ERR,  "File too short/long" },
    { ASN_CONSTRAINT_ERR, "Failed constraint test" },
    { ASN_RECURSION_ERR,  "Constraint calls forbidden function" },
    { ASN_ENUM_ERR,       "Item must be enumerated" },
    { ASN_FILE_ERR,       "Error opening file" },
    { 0,                  "Undefined error" },
    };

struct casn_err_struct casn_err_struct;

/* char_table masks are:
    numeric       1              ' ' = ia5 only,
    printable     4              '0' = ia5 & visible
    t61 (teletex) 8              '(' =  "  &t61
    visible    0x10              '8' =  " , visible & t61
    ia5        0x20              '<' =  " ,    "   ,   ", & printable
                                 '=' =  "  ,  "    ,   ",     "  & numeric
as agreed by John Lowry and Charlie Gardiner on May 23, 1996! and
corrected by CWG on May 3, 2001 */

char char_table[] = "\
        ( ( ((((\
         ((( (  \
=888888<<<8<<<<<\
==========<00<0<\
8<<<<<<<<<<<<<<<\
<<<<<<<<<<<80808\
0<<<<<<<<<<<<<<<\
<<<<<<<<<<<08000\
           ((   \
           (    \
 ((((((((  (    \
(((((((((  (((((\
 (((((((((((((((\
                \
((((( ((((((((((\
((((((((((((((( ",      // 0xE0 - 0xFF
    mask_table[32] = {0, 0, 0, 0, 0, 0, 0,    0, 0, 0, 0,    0, 0, 0, 0, 0,
                      0, 0, 1, 4, 8, 0, 0x20, 0, 0, 0, 0x10, 0, 0, 0, 0, 0};
              /*            N  P  T      I              V
                            u  r  6      A              i
                            m  t  1      5              s */

int casn_error(int, char *),
    _calc_lth(uchar **cpp, uchar ftag),
    _calc_lth_lth(int),
    _casn_obj_err(struct casn *, int),
    _check_enum(struct casn **casnpp),
    _check_filled(struct casn *casnp, int mode),
    _clear_error(struct casn *),
    _csize(struct casn *casnp, uchar *from, long lth),
    _encodesize(struct casn *casnp, uchar *to, int mode),
    _encode_tag_lth(uchar *to, struct casn **casnpp),
    _fill_upward(struct casn *casnp, int val),
    _readsize(struct casn *casnp, uchar *to, int mode),
    _readvsize(struct casn *casnp, uchar *to, int mode),
    _mark_definees(struct casn *casnp, uchar *wherep, int index),
    _match_casn(struct casn *casnp, uchar *from, int nbytes, ushort ff,
        ushort level, struct casn *of_casnp, int *had_indedfp),
    _num_casns(struct casn *casnp),
     _set_all_lths(uchar *top, uchar *tag_endp, uchar *val_endp, int mode),
    _set_casn_lth(uchar *s, uchar *e, int mode),
    _table_op(struct casn *casnp),
    _write_casn(struct casn *casnp, uchar *c, int lth),
    _write_enum(struct casn *casnp),
    _write_objid(struct casn *casnp, char *from);

void _clear_casn(struct casn *, ushort),
    *_clear_of(struct casn *casnp);

long _get_tag(uchar **tagpp);

void *_free_it(void *),
     _stuff_num(int count),
     _stuff_ofs(struct casn *casnp, int num_ofs),
     _stuff_string(struct casn *casnp);

struct casn *_find_chosen(struct casn *casnp),
            *_find_filled(struct casn *casnp),
            *_find_filled_or_chosen(struct casn *casnp, int *errp),
            *_find_flag(struct casn *casnp, int flag),
            *_find_tag(struct casn *casnp, ulong tag),
            *_go_up(struct casn *),
            *_dup_casn(struct casn *casnp),
            *_skip_casn(struct casn *casnp, int num);

void clear_casn(struct casn *casnp)
    {
    _clear_casn(casnp, ~(ASN_FILLED_FLAG | ASN_CHOSEN_FLAG));
    }

int decode_casn(struct casn *casnp, uchar *from)
    {
    uchar *c = from;
    int lth;

    _get_tag(&c);
    if ((lth = _calc_lth(&c, *from)) < -1)
        return _casn_obj_err(casnp, ASN_LENGTH_ERR);
    if (lth < 0) lth = 0x7fffffff;
    else lth += (c - from);
    return decode_casn_lth(casnp, from, lth);
    }

int decode_casn_lth(struct casn *casnp, uchar *from, int lth)
    {
    int has_indef = 0;
    if (_clear_error(casnp) < 0) return -1;
	  // don't clear it if it is defined_by
    if (!(casnp->flags & (ASN_CHOSEN_FLAG | ASN_DEFINED_FLAG)))
        _clear_casn(casnp, ~(ASN_FILLED_FLAG));
    int ansr = _match_casn(casnp, from, lth, (ushort)0, (short)0, 
      (struct casn *)0, &has_indef);
    casnp->flags |= has_indef;
    if (ansr < 0) log_msg(LOG_ERR, "ASN.1 decode error at %s, offset %d (0x%x)", 
      casn_err_struct.asn_map_string, -ansr, -ansr);
    return ansr;
    }

void delete_casn(struct casn *casnp)
    {
/**
Function: Frees all startps in every member, recursively
Input: Ptr to starting (top) struct casn
Output: Cleaned structure(s)
Procedure:
1. IF it's an OF with attachments, trim off the attachments
   IF it's a pointer
	IF it points to something
	    Delete what it points to
            Free the pointed to object
        Return
   IF it's constructed OR is a wrapper OR an enum, delete its members
   ELSE (it's primitive AND NOT (a wrapper OR a choice OR an enum))
	IF it has a startp, free that
	IF it's a definer
            FOR each remaining item after the path variable
                Free its startp
**/
    struct casn *ncasnp, *tcasnp;
    int num;

    if (_clear_error(casnp) < 0) return;
    if ((casnp->flags & ASN_OF_FLAG) && casnp[1].ptr)
        casnp[1].ptr = _clear_of(casnp[1].ptr);
    if ((casnp->flags & ASN_POINTER_FLAG))
	{
	if (casnp->ptr)
            {
            delete_casn(casnp->ptr);
            casnp->ptr = _free_it(casnp->ptr);
            }
        return;
	}
    if ((casnp->type & ASN_CONSTRUCTED) ||
        ((casnp->flags & ASN_ENUM_FLAG) && casnp->type != ASN_BITSTRING))
	{
	for (tcasnp = &casnp[1]; tcasnp; tcasnp = ncasnp)
	    {
            ncasnp = _skip_casn(tcasnp, 1);
	    delete_casn(tcasnp);
	    }
        if ((casnp->flags & ASN_ENUM_FLAG))  // free main one
          casnp->startp = _free_it(casnp->startp);
	}
    else
        {
        casnp->startp = _free_it(casnp->startp);
        if ((casnp->flags & ASN_TABLE_FLAG))
            {
            ncasnp = casnp->ptr;
            if (!ncasnp)
                {
                if (casnp->lth) _casn_obj_err(casnp, ASN_GEN_ERR);
                return;
                }
            for (num = (ncasnp++)->lth;  num--; ncasnp++)
                {
                ncasnp->startp = _free_it(ncasnp->startp);
                }
            casnp->ptr = _free_it(casnp->ptr);
            }
        }
        casnp->lth = 0;
    }

struct casn *dup_casn(struct casn *casnp)
    {
    if (!(casnp->flags & ASN_POINTER_FLAG)) return (struct casn *)0;
    return _dup_casn(casnp);
    }

int eject_casn(struct casn *casnp, int num)
    {
    struct casn *fcasnp, *pcasnp, *tcasnp;
    int icount, err = 0;

    if (_clear_error(casnp) < 0) return -1;
    if (!(casnp->flags & ASN_OF_FLAG)) err = ASN_OF_ERR;
    else
	{
        for (icount = 0, tcasnp = &casnp[1]; tcasnp->ptr; tcasnp = tcasnp->ptr,
            icount++);
        if (num >= icount) err = ASN_OF_BOUNDS_ERR;
	}
    if (err) return _casn_obj_err(casnp, err);
    fcasnp = &casnp[1];  // first member in OF
    if (!num)
	{
	tcasnp = fcasnp->ptr;  // mark second for deletion
        _clear_casn(fcasnp, ~(ASN_FILLED_FLAG));
        if (tcasnp->ptr)   // if second is not last
            copy_casn(fcasnp, tcasnp); //copy second to first
        else casnp->flags &= ~(ASN_FILLED_FLAG | ASN_CHOSEN_FLAG);
        fcasnp->ptr = tcasnp->ptr;  // make first point to where 2nd did
	}
    else
        {
        for (pcasnp = fcasnp, icount = num; --icount; pcasnp = pcasnp->ptr);
        tcasnp = pcasnp->ptr;
        pcasnp->ptr = tcasnp->ptr;
        }
    _clear_casn(tcasnp, ~(ASN_FILLED_FLAG));  // clearing is enough.
                         // Deleting would free definers
                         // in lower OF that should only be deleted when
                         // the lcasnp is deleted
    _free_it(tcasnp);
    casnp->num_items--;
    return num;
    }

int encode_casn(struct casn *casnp, uchar *to)
    {
    int ansr;

    if ((ansr = _clear_error(casnp)) < 0 ||
        (ansr = _check_filled(casnp, 0)) <= 0) return ansr;
    return _encodesize(casnp, to, ASN_READ);
    }

struct casn *index_casn(struct casn *casnp, int num)
    {
    struct casn *tcasnp;
    int err = 0;

    if (_clear_error(casnp) < 0) return (struct casn *)0;
    if (!casnp->level || !(_go_up(casnp)->flags & ASN_OF_FLAG))
        err = ASN_NOT_OF_ERR;
/*
    else
	{
        for (tcasnp = casnp ; num-- && tcasnp->ptr; tcasnp = tcasnp->ptr);
        if (num >= 0) err = ASN_OF_BOUNDS_ERR;
	}
*/
    else if (num >= casnp->num_items) err = ASN_OF_BOUNDS_ERR;
    if (err)
	{
	_casn_obj_err(casnp, err);
        return (struct casn *)0;
	}
    return tcasnp;
    }

struct casn *inject_casn(struct casn *casnp, int num)
    {
    struct casn *fcasnp = &casnp[1], // first member
        *lcasnp, *pcasnp, *tcasnp;
    int icount, ncount, err = 0;

    if (_clear_error(casnp) < 0) return (struct casn *)0;
    if (!(casnp->flags & ASN_OF_FLAG)) err = ASN_NOT_OF_ERR;
    else if ((err = _fill_upward(casnp, 0)) != 0) err = -err;
    else if(casnp->max && num >= casnp->max) err = ASN_OF_BOUNDS_ERR;
    if (err)
        {
        _casn_obj_err(casnp, err);
        return (struct casn *)0;
        }
    if (!casnp->num_items) casnp->lastp = fcasnp;
    ncount = _num_casns(casnp->lastp); // how many struct casns in this casnp
    tcasnp = (struct casn *)dbcalloc(ncount, sizeof(struct casn));
        // set up tags etc. in tcasnp. 
    if (!casnp->num_items) lcasnp = fcasnp;
    else lcasnp = casnp->lastp->ptr;
    memcpy(tcasnp, lcasnp, (ncount * sizeof(struct casn)));
    if (!num)   // has to go in front, but fcasnp must be first
	{
	if (!casnp->num_items) // there is only one, including final
    	    tcasnp->level = 0;  // fcasnp's ptr was null, so OK
        else  // there's more than one, including final
	    {
            copy_casn(tcasnp, fcasnp); // so copy the first to the new one
            tcasnp->ptr = fcasnp->ptr;  // make new one point to where first did
            _clear_casn(fcasnp, ~(ASN_FILLED_FLAG)); // clear the old first
	    }
	fcasnp->ptr = tcasnp;    // then link first one to new one
        tcasnp = fcasnp;   // return ptr to first
	}
    else // there's more than one, including final
      {   // if it's the last
     if (num == casnp->num_items) pcasnp = casnp->lastp;
          // else find previous item
      else for (pcasnp = fcasnp, icount = num; --icount; pcasnp = pcasnp->ptr);
        // copy blank last to new one
      tcasnp->ptr = pcasnp->ptr;   // new one points to where previous did
      pcasnp->ptr = tcasnp;       // previous points to new one
      if (num == casnp->num_items) casnp->lastp = tcasnp;
      tcasnp->level = 0;   // this may be redundant
      }
    casnp->num_items++;
    return tcasnp;
    }

struct casn *insert_casn(struct casn *casnp, int num)
    {
    struct casn *tcasnp;

    if (_clear_error(casnp) < 0) return (struct casn *)0;
    if (!casnp->level || !((tcasnp = _go_up(casnp))->flags & ASN_OF_FLAG) ||
        casnp != &tcasnp[1])
        {
        _casn_obj_err(casnp, ASN_NOT_OF_ERR);
        return (struct casn *)0;
        }
    return inject_casn(tcasnp, num);
    }

struct casn *member_casn(struct casn *casnp, int index)
    {
    struct casn *tcasnp;
    int err = 0;

    if (_clear_error(casnp) < 0) return (struct casn *)0;
    if (!(casnp->flags & ASN_OF_FLAG)) err = ASN_NOT_OF_ERR;
    else
	{
        for (tcasnp = &casnp[1] ; index-- && tcasnp->ptr; tcasnp = tcasnp->ptr);
        if (index >= 0 || !tcasnp->ptr) err = ASN_OF_BOUNDS_ERR;
	}
    if (err)
      {
      _casn_obj_err(casnp, err);
      tcasnp = (struct casn *)0;
      }
    return tcasnp;
    }

struct casn *next_of(struct casn *casnp)
    {
    int err = 0;

    if (casnp->level && !(_go_up(casnp)->flags & ASN_OF_FLAG))
        err = ASN_TYPE_ERR;
    else if (!casnp->ptr) err = ASN_OF_BOUNDS_ERR;
    if (err) _casn_obj_err(casnp, err);
    else
	{
        casnp = casnp->ptr;
        if (casnp->ptr) return casnp;
	}
    return (struct casn *)0;
    }

int num_items(struct casn *casnp)
    {
    int num;

    if (_clear_error(casnp) < 0) return -1;
    if (!(casnp->type & ASN_CONSTRUCTED) || !(casnp->flags & ASN_OF_FLAG))
	return _casn_obj_err(casnp, ASN_NOT_OF_ERR);
    for (casnp++, num = 0; casnp->ptr; casnp = casnp->ptr, num++);
    return num;
    }

int read_casn(struct casn *casnp, uchar *to)
    {
    return _readvsize(casnp, to, ASN_READ);
    }

int remove_casn(struct casn *casnp, int num)
    {
    struct casn *tcasnp;

    if (_clear_error(casnp) < 0) return -1;
    if (!casnp->level || !((tcasnp = _go_up(casnp))->flags & ASN_OF_FLAG))
        return _casn_obj_err(casnp, ASN_OF_ERR);
    return eject_casn(tcasnp, num);
    }

void simple_constructor(struct casn *casnp, ushort level, int type)
    {
    tagged_constructor(casnp, level, type, type);
    }

int size_casn(struct casn *casnp)
    {
    uchar buf[4];
    int ansr;

    if ((ansr = _clear_error(casnp)) < 0 ||
        (ansr = _check_filled(casnp, 0)) <= 0) return ansr;
    return _encodesize(casnp, buf, 0);
    }

void tagged_constructor(struct casn *casnp, ushort level, int type, int tag)
    {
    memset(casnp, 0, sizeof(struct casn));
    casnp->level = level;
    casnp->type = type;
    casnp->tag = tag;
    }

int tag_casn(struct casn *casnp)
    {
    int val, tmp;

    if (_clear_error(casnp) < 0) return -1;
    if (casnp->type == ASN_CHOICE && !(casnp = _find_filled(casnp))) return 0;
    for (tmp = casnp->tag, val = 0; tmp; val = (val << 8) + (tmp & 0xFF),
	tmp >>= 8);
    return val;
    }

int vsize_casn(struct casn *casnp)
    {
    uchar buf[4];

    return _readvsize(casnp, buf, 0);
    }

int write_casn(struct casn *casnp, uchar *c, int lth)
    {
    struct casn *tcasnp;
    int err = 0;

    if (_clear_error(casnp) < 0) return -1;
    if (casnp->tag == ASN_NOTYPE) return _write_enum(casnp);
    if (casnp->type == ASN_CHOICE && (casnp->flags & ASN_DEFINED_FLAG) &&
	     // only if it's a pure defined by
	!(casnp = _find_chosen(casnp))) err =  ASN_NO_DEF_ERR;
    if (!err && casnp->level) tcasnp = _go_up(casnp);
    else tcasnp = (struct casn *)0;
    if (!err && tcasnp)
	{
        if ((tcasnp->flags & ASN_DEFINED_FLAG) &&
            !(casnp->flags & ASN_CHOSEN_FLAG)) err = ASN_NO_DEF_ERR;
	    // trying to write to first & only member of OF?
	else if ((tcasnp->flags & ASN_OF_FLAG) && casnp == &tcasnp[1] &&
            !casnp->ptr) err = ASN_OF_BOUNDS_ERR;
	}
    if (err) return _casn_obj_err(casnp, err);
    return _write_casn(casnp, c, lth);
    }

int _calc_lth(uchar **cpp, uchar ftag)
    {
    uchar *c = *cpp;
    int tmp, lth;

    if (*c > 0x84 || (*c == 0x84 && c[1] > 0x7F)) return -2;
    if(*c == ASN_INDEF_LTH) 
      { 
      *cpp = ++c;
      return -1;
      }
    if (((lth = *c++) & ASN_INDEF_LTH))
      {
      if ((tmp = (lth &= (uchar)~ASN_INDEF_LTH)))
        {
        for (lth = 0; tmp--; lth = (lth << 8) + *c++);
        }
      }
    *cpp = c;
    return lth;
    }

int _calc_lth_lth(lth)
    int lth;
    {
    int fwd;
    if (lth < 128) return 0;
    for (fwd = 0; lth; fwd++, lth >>= 8);
    return fwd;
    }

int _casn_obj_err(struct casn *casnp, int num)
    {
    struct casn_errors *errp;
    for (errp = casn_errors; errp->num && errp->num != num; errp++);
    casn_error(errp->num, errp->msg);
    casn_err_struct.errnum = num;
    casn_err_struct.casnp = casnp;
    casn_err_struct.asn_map_string = _free_it(casn_err_struct.asn_map_string);
    _stuff_string(casnp);
    return -1;
    }

int _check_enum(struct casn **casnpp)
    {
    struct casn *tcasnp;

    if (!(tcasnp = _go_up(*casnpp))) return -1;
    if ((*casnpp)->lth != tcasnp->lth ||
         memcmp((*casnpp)->startp, tcasnp->startp, tcasnp->lth)) return 0;
    *casnpp = tcasnp;
    return 1;
    }

int _check_filled(struct casn *casnp, int mode)
    {
    ushort flags = (casnp->flags & (ASN_DEFAULT_FLAG | ASN_OPTIONAL_FLAG));

    if ((casnp->flags & ASN_FILLED_FLAG)) return 1;
    if (casnp->type >= ASN_CHOICE && (casnp->flags & ASN_DEFINED_FLAG))
        casnp = _find_chosen(casnp);
  	  // error if couldn't find chosen OR (it's not a NONE AND not OPTIONAL)
    if (!casnp || (!flags && casnp->type != ASN_NONE))
        {
        if ((mode & ASN_READ)) return _casn_obj_err(casnp, ASN_MANDATORY_ERR);
	}
    return 0;
    }

void _clear_casn(struct casn *casnp, ushort mask)
    {
/**
Function: Clears all memory allocated by decoding and all flags set by decoding
Input: Ptr to top struct casn
       Mask for flag bits
Procedure:
1. IF it's an OF AND has some members, clear the attached ones
   IF it's constructed
        FOR each member, call _clear_casn
   ELSE IF it has a startp, free that
   Clear num_items and lastp
   Clear the flags in accordance with the mask
   IF the type is an ANY, set the tag to that
**/
    struct casn *tcasnp;

    if (_clear_error(casnp) < 0) return;
    if ((casnp->flags & ASN_OF_FLAG) && casnp[1].ptr)
        casnp[1].ptr = _clear_of(casnp[1].ptr);
    if ((casnp->type & ASN_CONSTRUCTED))
	{
	for (tcasnp = &casnp[1]; tcasnp; tcasnp = _skip_casn(tcasnp, 1))
	    {
            _clear_casn(tcasnp, mask);
	    }
	}
    else
        {
        casnp->startp = _free_it(casnp->startp);
        casnp->lth = 0;
        }
    casnp->num_items = 0;
    casnp->lastp = NULL;
    casnp->flags &= mask;
    if (!casnp->type) casnp->tag = ASN_ANY;
    }

int _clear_error(struct casn *casnp)
    {
    casn_err_struct.asn_map_string = _free_it(casn_err_struct.asn_map_string);
    casn_err_struct.casnp = (struct casn *)0;
    if (!casnp) return _casn_obj_err((struct casn *)0, ASN_NULL_PTR);
    return 1;
    }

void *_clear_of(struct casn *casnp)
    {
/**
Function: Clears an OF chain
Input: Ptr to struct casn of a member AFTER the first
Procedure
1. WHILE there's more to the chain
       Note to where it points
       Clear current item
       Make pointed-to-item current
   (Now casnp points to the last item)
   Free end of chain (it can't have any attachments)
**/
    struct casn *ncasnp;

    while (casnp->ptr)
        {
        ncasnp = casnp->ptr;
        casnp->ptr = (struct casn *)0;
        clear_casn(casnp);
        _free_it(casnp);
        casnp = ncasnp;
        }
    clear_casn(casnp); // clear the last one
    return _free_it(casnp);
    }

int _csize(struct casn *casnp, uchar *from, long lth)
    {
    int tlth;
    uchar *e = &from[lth];
    uchar typ;

    if (casnp->type == ASN_UNIVERSAL_STRING) return (lth + 3) / 4;
    else if (casnp->type == ASN_BMP_STRING) return (lth + 1) / 2;
    else if (casnp->type == ASN_UTF8_STRING)
        {
        for (lth = 0; from < e; lth++)
            {
            if (*from == 0xFE || *from == 0xFF) return -1;
            for (typ = *from, tlth = -1; typ & 0x80; typ <<= 1, tlth++);
            for (from++; tlth-- >= 0 && (*from & 0xC0) == 0x80; from++);
            if (tlth >= 0 || from > e) return -1;
            }
        }
    return lth;
    }

struct casn *_dup_casn(struct casn *casnp)
    {
    int err = 0;
    _free_it(casnp->ptr);
    casnp->ptr = (struct casn *)dbcalloc(1, casnp->min);
    ((void(*)(void *, ushort))casnp->startp)((void *)casnp->ptr, 0);
    if ((err = _fill_upward(casnp, ASN_FILLED_FLAG)) < 0)    // assumes duped object will be
        {           // filled. writing pointed-to won't go up through pointer
        _casn_obj_err(casnp, -err);
        casnp = (struct casn *)0;
        }
    return casnp->ptr;
    }

int _encode_tag_lth(uchar *to, struct casn **casnpp)
    {
    ulong tag;
    uchar *c;
    struct casn *casnp = *casnpp;

    if (casnp->type == ASN_NOTASN1) return 0;
    while (casnp->type == ASN_CHOICE && casnp->tag == ASN_CHOICE &&
        !(casnp->flags & ASN_EXPLICIT_FLAG))
	{
	if ((casnp->flags & ASN_DEFAULT_FLAG)) casnp = _find_chosen(casnp);
        else casnp = _find_filled(casnp);
        if (!casnp) return -1;
	}
    for (tag = casnp->tag, c = to; tag; *c++ = (tag & 0xFF), tag >>= 8);
    *c++ = 0;
        // IF (explicit AND (neither a choice NOR nonANY DEFINED BY)) OR
        // a tagged choice
        // need to do inner tag, too
    if (((casnp->flags & ASN_EXPLICIT_FLAG) && casnp->type != ASN_CHOICE) ||
        (casnp->type == ASN_CHOICE && casnp->tag < ASN_CHOICE &&
        !(casnp->tag & ASN_CONSTRUCTED)))
	{
	// IF explicitly tagged nonANY DEFINED BY, do that tag
        if (casnp->type > ASN_CHOICE)
	    {
            *c++ = casnp->type - ASN_CHOICE;
	    *c++ = 0;
	    }  // now do the chosen's tag
	if ((casnp->type >= ASN_CHOICE && (casnp->flags & ASN_DEFINED_FLAG) &&
            !(casnp = _find_chosen(casnp))) ||
	    (casnp->type == ASN_CHOICE && !(casnp = _find_filled(casnp))))
            return -1;
        for (tag = (casnp->type)? casnp->type: casnp->tag; tag;
            *c++ = (tag & 0xFF), tag >>= 8);
	*c++ = 0;
	}
    *casnpp = casnp;
    return c - to;
    }

int _encodesize(struct casn *casnp, uchar *to, int mode)
    {
    uchar *c, *contp, buf[8];
    int i, lth;
    struct casn *tcasnp;

    if (!(mode & ASN_READ)) to = buf;
    c = to;
    if ((lth = _check_filled(casnp, 1)) <= 0) return lth;
    if ((casnp->flags & ASN_POINTER_FLAG))
	{
	if (!casnp->ptr) return 0;
	casnp = casnp->ptr;
	}
    if ((casnp->flags & ASN_DEFAULT_FLAG))
	{
	if ((casnp->flags & ASN_DEFINED_FLAG)) tcasnp = _find_chosen(casnp);
	else tcasnp = casnp;
        if (tcasnp->type == ASN_BOOLEAN)
	    {
	    if (tcasnp->startp) i = *tcasnp->startp;
	    else i = 0;     // does it match the prescribed value?
	    if ((tcasnp->min & BOOL_DEFINED) && (i == 0) !=
                ((tcasnp->min & BOOL_DEFINED_VAL) == 0))
		return _casn_obj_err(tcasnp, ASN_CONSTRAINT_ERR);
		        // if at the default, return 0
	    if ((i == 0) == ((tcasnp->min & BOOL_DEFAULT) == 0)) return 0;
	    }
        else
    	    {
    	    if (!(casnp->flags & ASN_ENUM_FLAG))
                return _casn_obj_err(casnp, ASN_ENUM_ERR);
    	    for (tcasnp = &casnp[1]; tcasnp &&
                !(tcasnp->flags & ASN_DEFAULT_FLAG);
    	        tcasnp = _skip_casn(tcasnp, 1));
    	    if (!tcasnp)
                return _casn_obj_err(casnp, ASN_ENUM_ERR);
    	    if (tcasnp->lth == casnp->lth &&
                !memcmp(tcasnp->startp, casnp->startp, casnp->lth)) return 0;
    	    }
        }
    tcasnp = casnp;
    if ((lth = _encode_tag_lth(c, &tcasnp)) < 0)
        return _casn_obj_err(&casnp[1], ASN_MATCH_ERR);
    contp = c += lth;   // contp marks end of tags
    if (tcasnp != casnp && tcasnp->type == ASN_CHOICE && (tcasnp->flags &
	ASN_EXPLICIT_FLAG))
	{
	tcasnp = _find_filled(tcasnp);
	i = _encodesize(tcasnp, c, mode);
	}
    else if ((i = _readsize(tcasnp, c, mode)) < 0) return i - lth;
    c += i;
    lth += i;
    if (contp > to) lth += _set_all_lths(to, contp, c, mode);
    return lth;
    }

int _fill_upward(struct casn *casnp, int val)
    {
    struct casn *ucasnp;

    for ( ; casnp && !(casnp->flags & val); casnp = ucasnp)
	{
        ucasnp = _go_up(casnp);
        if (ucasnp)
          {   // writing to terminal OF?
          if ((ucasnp->flags & ASN_OF_FLAG) && !casnp->ptr)
            return -(ASN_OF_BOUNDS_ERR);
              // writing or injecting to unchosen definee?
          if ((ucasnp->type & ASN_CHOICE) == ASN_CHOICE &&
            (ucasnp->flags & ASN_DEFINED_FLAG) > 0 &&
            (casnp->flags & ASN_CHOSEN_FLAG) == 0)
            return -(ASN_NO_DEF_ERR);
          }
	casnp->flags |= val;
	}
    return 0;
    }

struct casn *_find_tag(struct casn *casnp, ulong tag)
    {
    struct casn *tcasnp;

    while (casnp)
	{
        if (casnp->tag == tag || casnp->type == ASN_ANY) return casnp;
	if (casnp->type == ASN_CHOICE && (tcasnp = _find_tag(&casnp[1], tag)))
            return tcasnp;
        casnp = _skip_casn(casnp, 1);
	}
    return casnp;
    }

struct casn *_find_chosen(struct casn *casnp)
    {
    return _find_flag(casnp, ASN_CHOSEN_FLAG);
    }

struct casn *_find_filled(struct casn *casnp)
    {
    return _find_flag(casnp, ASN_FILLED_FLAG);
    }

struct casn *_find_filled_or_chosen(struct casn *casnp, int *errp)
    {
    if ((casnp->flags & ASN_DEFINED_FLAG))
	{
	if (!(casnp = _find_chosen(casnp))) *errp = ASN_NO_DEF_ERR;
	}
    else if (!(casnp = _find_filled(casnp))) *errp = ASN_MANDATORY_ERR;
    return casnp;
    }

struct casn *_find_flag(struct casn *casnp, int flag)
    {
    for (casnp++; casnp && !(casnp->flags & flag);
	    casnp = _skip_casn(casnp, 1));
    return casnp;
    }

void *_free_it(void *itp)
    {
    if (itp) free(itp);
    return (void *)0;
    }

long _count_crumbs_size(uchar *fromp)
  {
  uchar *c;
  long ansr = 0;
  long lth;
  for (c = fromp; *c || c[1]; c += lth)
    {
    c++;  // go to length field;
    lth = _calc_lth(&c, (uchar)0); // c ends at 1st data byte
    ansr += lth;
    } 
  return ansr;
  }  

long _gather_crumbs(uchar **topp, uchar **frompp)
  {
  uchar *c = *frompp;
  uchar *startp = 0, *curr_endp;
  int lth, tot_lth;
  tot_lth = _count_crumbs_size(*frompp);
  if (!(startp = (uchar *)calloc(1, tot_lth))) return -1;
  for (curr_endp = startp; *c || c[1]; c += lth) 
    {
    c++;  // c goes to length field
    lth  = _calc_lth(&c, (uchar)0);  // c ends at 1st data byte
    memcpy(curr_endp, c, lth);
    curr_endp += lth;
    }  
// reached the double null
  *frompp = c;
  *topp = startp;
  return tot_lth;
  }
  
long _get_tag(uchar **tagpp)
    {
    uchar *c = *tagpp;
    long ansr, tmp;
    int shift;

    if (((ansr = *c) & 0x1F) == 0x1F)
        {
        shift = 8;
        do
            {
            tmp = *(++c);
            tmp <<= shift;
            ansr |= tmp;
            shift += 8;
            }
        while ((*c & 0x80));
        }
    *tagpp = ++c;
    return ansr;
    }

struct casn *_go_up(struct casn *casnp)
    {
    int lev;

    if (!casnp->level) return (struct casn *)0;

    for (lev = casnp->level; casnp->level >= lev; casnp--);
    return casnp;
    }

int _mark_definees(struct casn *casnp, uchar *wherep, int index)
    {
    struct casn *tcasnp;
    int tmp;

    for (tcasnp = casnp; 1; wherep++)
        {
        if (*wherep <= ' ')
            {
	    if (!(tcasnp->flags & ASN_DEFINED_FLAG) ||
		tcasnp->type < ASN_CHOICE) return 0;
	    clear_casn(tcasnp);
            for (tmp = index, tcasnp++; tmp-- && tcasnp;
                tcasnp = _skip_casn(tcasnp, 1));
            if (!tcasnp) return 0;
            tcasnp->flags |= ASN_CHOSEN_FLAG;
            if (!*wherep) break;
            tcasnp = casnp;    // prepare for next definee
            }
        else if (*wherep == '-')
            {
            if (!(tcasnp = _go_up(tcasnp))) return 0;
            }
        else if (*wherep > '0')
            {
	    if (!(tcasnp = _skip_casn(tcasnp, (int)(*wherep - '0'))) ||
		// if more than 1 'digit', go down
                (wherep[1] >= '0' && (!(tcasnp++)->type & ASN_CONSTRUCTED)))
            return 0;
            }
        }
    return 1;
    }

int _match_casn(struct casn *casnp, uchar *from, int nbytes, ushort pflags,
    ushort this_level, struct casn *of_casnp, int *had_indefp)
    {
/**
Function: Decodes a stream, starting at 'from' for 'nbytes' bytes, filling in
'casnp'
Inputs: Ptr to struct casn
        Ptr to start of stream
        Number of bytes in stream
	Flags from parent, e.g., OF flag
	Indicator as to whether there are members (0= no)
Output: Number of bytes decoded.  IF error, negative of number decoded up to
        error point.
Procedure:
1. IF this is an OF or a SET, set the of_casnp ptr, ELSE clear it
2. FOR all items in the structure at this level
        IF it's an OF
            IF can't inject the next member, return error
            Set the current ptr to that
3.      Get the tag from the stream and the flags from the struct casn
        IF (at a DEFINED BY that's not a wrapper) OR at a CHOICE OR in a SET
          WHILE in a 
	    IF at a tagged CHOICE, get the next tag
            IF at a DEFINED BY
                Find the definee
                IF that's a CHOICE, find the chosen
            ELSE (CHOICE OR SET)
              Search from the next struct casn to find the desired one
	      IF that's already filled, return error
            Make that the current struct casn
	ELSE IF tag doesn't match
            IF not at a default OR optional item, return error
            iF no next struct casn at this level, return error
            Reset pointer to before this tag
            Try again
	IF it's a pointer
	    Get space for the struct needed
	    Call the constructor
	    Make the pointed-to be the current item
        IF have indefinite length, return error
        Calculate the length
        Count up the bytes processed so far
        IF have overshot or will with this item, return error
4.	IF at an explicitly tagged item that's empty, return error
	IF at an explicitly tagged item OR at a choice where the current tag 
            is not the type
            Get the next tag and length
            IF current type is nonANY DEFINED by
              Get the desired type (current type - ASN_CHOICE) 
              IF this item is explicit AND the tag is not equal to the type 
                IF the tag is not a constructed version of the type, error
                IF the length is indefinite, increment indefs
                Get next tag and length
                IF tag matches expected type
                  IF indefinite length, increment indefs 
            ELSE IF item is explicit AND tag not equal to current type OR
              item is not explicit AND tag not equal to current tag, error
            IF too many bytes, error
        Check that the next byte matches the type
	    IF have indefinite length, return error
	    Calculate the length
        ELSE IF at a CHOICE where the current tag is not the type
          Get the tag and length
           
        IF at a primitive item which isn't a wrapper
            Note what the call to write a primitive returns.
        ELSE IF current item has no contents, its length is zero
        ELSE
	    IF at a defined member, choose the chosen one
            ELSE choose the next struct casn
            IF at a BIT STRING wrapper, add one to start point
            IF call to decode with the chosen struct casn from start point
                returns error, return error
                    IF have overshot, return error
        Advance the start pointer
5.      IF at an OF OR in a SET, reset struct casn ptr
        ELSE IF not at the top level that was asked for
            Skip to next struct casn at this level
            IF have done all bytes
		IF item we just did wasn't a chosen
                    IF there is a mandatory item at this level, return error
            ELSE IF have no more struct casns, return error
   Return count of bytes processed
**/
    struct casn *curr_casnp, *ch_casnp, *sav_casnp, *set_casnp,
        *tcasnp;
    int ansr, did, err, num, lth, explicit_extra, break_out, num_ofs,
      indefs = 0, has_indef, skip_match;
    uchar *b, *c, ftag = 0;
    long tag;
    ushort flags, level, send_flag;
							// step 1
    set_casnp = (struct casn *)0;
    if ((pflags & ASN_SET_FLAG)) set_casnp = casnp;  // to go back to each time
							// step 2
    for (num_ofs = did = 0, curr_casnp = casnp; (!nbytes || nbytes > did); )
        {
        int def_lth = 0;
        has_indef = skip_match = 0;
        if (!curr_casnp) return _casn_obj_err(curr_casnp, ASN_MATCH_ERR) - did;
        c = from;  // note that NONE case uses this to reset c
	err = 0;
        if (of_casnp)
	    {
            if (!(curr_casnp = inject_casn(of_casnp, num_ofs++)))
    	        return _casn_obj_err(of_casnp, ASN_OF_BOUNDS_ERR) - did;
	    }
							    // step 3
        ch_casnp = (struct casn *)0;
        ftag = *c;
        tag = _get_tag(&c);   // c is now at length
        flags = curr_casnp->flags;
        sav_casnp = curr_casnp;
        if ((curr_casnp->type == ASN_CHOICE && (curr_casnp->tag >= ASN_CHOICE ||
            curr_casnp->tag == tag)) || (pflags & ASN_SET_FLAG))
            {
	    while ((pflags & ASN_SET_FLAG) ||
		(curr_casnp->type == ASN_CHOICE &&
		((flags & ASN_DEFINED_FLAG) ||
		curr_casnp->tag >= ASN_CHOICE || curr_casnp->tag == tag)))
                {
		break_out = 0;
	        if (curr_casnp->type == ASN_CHOICE && // implicit tagged choice
						      // must be explicit
                    curr_casnp->tag == tag &&
                    !(curr_casnp->flags & ASN_DEFINED_FLAG))
		    {
            	    if ((lth = _calc_lth(&c, ftag)) < -1)
                        return _casn_obj_err(curr_casnp, ASN_LENGTH_ERR) - did;
                    (ch_casnp = curr_casnp)->lth = lth;
		    tag = _get_tag(&c);
		    }
        	if ((curr_casnp->flags & ASN_DEFINED_FLAG))
                    {
                    ch_casnp = _find_chosen(curr_casnp);
                    if (ch_casnp && ch_casnp->type == ASN_CHOICE)
                      ch_casnp = _find_tag(&ch_casnp[1], tag);
                    }
		else ch_casnp =
                    _find_tag(&curr_casnp[(pflags & ASN_SET_FLAG)? 0: 1], tag);
	        if (ch_casnp && ch_casnp->type == ASN_NONE)
		    {   // try again with next struct casn
		    curr_casnp = _skip_casn(curr_casnp, 1);
		    break_out = 1;
                    break;
		    }
		if (ch_casnp && ch_casnp->type == ASN_ANY) ch_casnp->tag = tag;
                if (!ch_casnp)
                    return _casn_obj_err(curr_casnp, ASN_MATCH_ERR) - did + 1;
                                          // extra part below for a taged choice
                flags = (ch_casnp->flags | 
                  (curr_casnp->flags & ASN_EXPLICIT_FLAG));
                
                curr_casnp = ch_casnp;
		if (pflags & ASN_SET_FLAG) break;
                }
	    if (break_out) ch_casnp = curr_casnp;
	    else if ((sav_casnp->flags & ASN_EXPLICIT_FLAG))
                ch_casnp = sav_casnp;
	    if (ch_casnp->tag != tag)
		{
		if (!(sav_casnp->flags & ASN_DEFAULT_FLAG))
    		    return _casn_obj_err(curr_casnp, ASN_MATCH_ERR) -did + 1;
		else    // try the next one
		    {
		    curr_casnp = _skip_casn(sav_casnp, 1);
                    break_out = 1;
		    }
		}
	    if (break_out) continue;
            }
        else if (curr_casnp->type == ASN_ANY) curr_casnp->tag = tag;
	else if (curr_casnp->tag != tag)
            {       // note that DEFAULTs are OPTIONAL, too
            struct casn *acasnp = curr_casnp;
    	    if ((curr_casnp->flags & ASN_OPTIONAL_FLAG) == 0 ||
	        !(curr_casnp = _skip_casn(curr_casnp, 1)))
                    return _casn_obj_err(acasnp, ASN_MATCH_ERR) - did - 1;
	    sav_casnp = curr_casnp;
	    continue;
	    }
	if ((curr_casnp->flags & ASN_POINTER_FLAG))
            curr_casnp = _dup_casn(curr_casnp);
	if ((lth = _calc_lth(&c, ftag)) < -1)
            return _casn_obj_err(curr_casnp, ASN_LENGTH_ERR) - did - 1;
        if (lth == -1) 
          {
          lth = ASN_UNDEFINED_LTH;
          indefs++;
          curr_casnp->flags |= ASN_INDEF_LTH_FLAG;
          sav_casnp->flags |= ASN_INDEF_LTH_FLAG;
          *had_indefp |= ASN_INDEF_LTH_FLAG;
          }
        curr_casnp->lth = (lth < ASN_UNDEFINED_LTH)? lth: nbytes;
        did += c - from;
        level = sav_casnp->level;
        if (nbytes && (did + lth > nbytes))
            return _casn_obj_err(curr_casnp, ASN_MATCH_ERR) - did - 1;
                                                            // step 4
	explicit_extra = 0;
	if ((flags & ASN_EXPLICIT_FLAG) && lth == 0)
            return _casn_obj_err(curr_casnp, ASN_MATCH_ERR) - did - 1;
	if ((flags & ASN_EXPLICIT_FLAG) ||
            (curr_casnp->type == ASN_CHOICE && tag != curr_casnp->type))
	    {
	    b = c;
	    tag = _get_tag(&c);
	    if ((lth = _calc_lth(&c, *b)) < -1)
                return _casn_obj_err(curr_casnp, ASN_LENGTH_ERR);
            if (lth == -1) 
              {
              lth = ASN_UNDEFINED_LTH;
              indefs++;
              curr_casnp->flags |= ASN_INDEF_LTH_FLAG;
              *had_indefp |= ASN_INDEF_LTH_FLAG;
              }
	    explicit_extra = (c - b);
		//test inner tag
		// first deal with explicit nonANY DEFINED BY
	    if (curr_casnp->type > ASN_CHOICE)
              {
              ansr = (curr_casnp->type & ~(ASN_CHOICE));
              if ((curr_casnp->flags & ASN_EXPLICIT_FLAG) && 
                ansr != curr_casnp->type)
                {
                if (tag == (ansr | ASN_CONSTRUCTED))  
                  {
                  if (*c != ansr) return -1;
                  did += explicit_extra;
                  uchar *cc, *oldc = c;
                  int newlth = _gather_crumbs(&cc, &c); 
                  if (newlth < 0) return ASN_LENGTH_ERR;
                  if (!(tcasnp = _find_chosen(curr_casnp))) 
                    return ASN_MATCH_ERR;
                  ansr = _match_casn(tcasnp, cc, newlth, 0, 
                     this_level + 1, NULL, had_indefp);
                  free(cc);
                  if (ansr < 0) return ASN_LENGTH_ERR;
                  ansr = c - oldc;   // how much to advance 'c'
                  def_lth = skip_match = 1;
                  }
                }
              } 
            else if(curr_casnp->type != ASN_ANY)
              {
              int x;
              if (curr_casnp->flags & ASN_EXPLICIT_FLAG) x = curr_casnp->type;
              else x = curr_casnp->tag;
              if (tag != x)  
                  return _casn_obj_err(curr_casnp, ASN_MATCH_ERR) - did - 1;
              }
            if (!skip_match)
              {
              did += explicit_extra;
              if (nbytes >= 0 && did + lth > nbytes)
                  return _casn_obj_err(curr_casnp, ASN_MATCH_ERR);
              }   
            } 
        if (!skip_match)
          {
    	  ansr = -1;
            // IF at a primitive item which isn't a wrapper
            //    Note what the call to write a primitive returns.
    	  if (!(curr_casnp->type & ASN_CONSTRUCTED))
    	    {
            if (casnp->level && (_go_up(casnp)->flags & ASN_DEFINED_FLAG) &&
              !(casnp->flags & ASN_CHOSEN_FLAG))
              return _casn_obj_err(casnp, ASN_NO_DEF_ERR) - did;
    	    if ((ansr = _write_casn(curr_casnp, c, lth)) < 0)
    	      {  // if first OF, casn_obj_err stuffed right on up
    	      if (of_casnp && num_ofs > 1) _stuff_ofs(of_casnp, num_ofs);
                    return ansr - did;
              }
    	    }
      	  else if (!curr_casnp->lth)
    	    {
    	    if (curr_casnp->min)
               return _casn_obj_err(curr_casnp, ASN_OF_BOUNDS_ERR);
            if ((ansr = _fill_upward(curr_casnp, ASN_FILLED_FLAG)) < 0)
               return _casn_obj_err(curr_casnp, -ansr);
            ansr = 0;
    	    }
     	  else
            {
            int ch = 0;
           //  	 IF at a defined member, choose the chosen one
    	    if (curr_casnp->type >= ASN_CHOICE)
              {
              ch = 1;
              if (!(tcasnp = _find_chosen(curr_casnp)) ||
                  (tcasnp->type == ASN_NOTASN1 &&
                  (ansr = _write_casn(tcasnp, c, lth)) < 0))
                      return ansr - did;
              }
             //      ELSE choose the next struct casn
            else tcasnp = &curr_casnp[1];
    	    if (ansr < 0)    // didn't have ASN_NOT_ASN1
    	      {
              struct casn *offp = (struct casn *)0;
              num = send_flag = 0;
              if (tag == ASN_BITSTRING) num = 1;
                // if was chosen, can't be an OF
              if (!ch && (curr_casnp->flags & ASN_OF_FLAG))
                {
                send_flag = ASN_OF_FLAG;
                offp = curr_casnp;
                }
              if (curr_casnp->type == ASN_SET) send_flag |= ASN_SET_FLAG;
              int xlth;
              if (def_lth) xlth = def_lth;
              else if (lth == ASN_UNDEFINED_LTH) xlth = lth;
              else xlth = curr_casnp->lth - explicit_extra - num;
              if ((ansr = _match_casn(tcasnp, &c[num],
                  xlth, send_flag, this_level + 1, offp, &has_indef)) < 0)
    	        {  // if first OF, casn_obj_err stuffed right on up
    	         if (of_casnp && num_ofs > 1) _stuff_ofs(of_casnp, num_ofs);
                        return ansr - did;
    	        }    // then pass the indef flag up
              *had_indefp |= has_indef;
              curr_casnp->flags |= has_indef;
              if (sav_casnp && curr_casnp != sav_casnp) 
                sav_casnp->flags |= has_indef;
              ansr += num;
              }
            }
          c += ansr;
          }
        if ((did += ansr) > nbytes && nbytes)
            return _casn_obj_err(curr_casnp, ASN_MATCH_ERR);
        if (indefs)
          {
          if (*c || c[1]) continue;
          while (indefs && *c == 0 && c[1] == 0)
            {
            indefs--;
            c += 2;
            did += 2;
            }
          curr_casnp->flags |= ASN_INDEF_LTH_FLAG;
          if (def_lth) nbytes = did;  // to force for loop in step 5
          } 
        if (nbytes == 0x7FFFFFFF && *c == 0 && c[1] == 0)
          return did;   // indefs to be processed by parent
        from = c;
							    // step 5
        if (!of_casnp && this_level)
            {
	    if ((pflags & ASN_SET_FLAG)) curr_casnp = set_casnp;
            else curr_casnp = _skip_casn(sav_casnp, 1);
    	    if (did == nbytes)  // all done
    	        {    // are any remining defined members all optional?
	        if (!(flags & ASN_CHOSEN_FLAG))
		    {   // if chosen, don't look at remaining items
                    for (num = 0; curr_casnp && curr_casnp->level == level;
        	        curr_casnp = _skip_casn(curr_casnp, 1))
        	        {   // is there a chosen member that must be present?
			if ((curr_casnp->flags &
                            (ASN_DEFINED_FLAG | ASN_OPTIONAL_FLAG)) ==
			    ASN_DEFINED_FLAG)
			    {
			    tcasnp = _find_chosen(curr_casnp);
			    if (!tcasnp || (tcasnp->type != ASN_NONE ||
                               (tcasnp->flags & ASN_OPTIONAL_FLAG))) num = 1;
			    }   // or another member that must be present?
        	        else if (!(curr_casnp->flags &
                            (ASN_OPTIONAL_FLAG | ASN_FILLED_FLAG))) num = 1;
                        if (num)
			    {
                            _casn_obj_err(curr_casnp, ASN_MANDATORY_ERR);
			    return -did;
			    }
        	        }
                    }
		}
    	    else if (!curr_casnp)     // have no more struct casns
              return _casn_obj_err(curr_casnp, ASN_MATCH_ERR) - did;
            }
        }  // end of for loop
    return did;
    }

int _num_casns(struct casn *casnp)
    {
    int ansr;

    if ((casnp->flags & ASN_POINTER_FLAG)) return 1;
    for (ansr = 0; casnp; casnp = _skip_casn(casnp, 1), ansr++)
        {
        if ((casnp->type & ASN_CONSTRUCTED) || casnp->type >= ASN_CHOICE ||
            (casnp->flags & ASN_ENUM_FLAG))
            ansr += _num_casns(&casnp[1]);
        }
    return ansr;
    }


void _put_asn_lth(uchar *start, int lth)
    {
    uchar *c;
    if (lth < 128) start[-1] = lth;
    else
        {
        for (c = start; lth; *(--c) = lth & 0xFF, lth >>= 8);
        c[-1] = (ASN_INDEF_LTH + (start - c));
        }
    }

char *_putd(char *to, long val)
    {
    long tmp = val / 10;

    if (tmp) to = _putd(to, tmp);
    *to++ = (char)((val % 10) + '0');
    return to;
    }
int _readsize(struct casn *casnp, uchar *to, int mode)
    {
    uchar bb, *b, *c, buf[8];
    int i, lth, num, of;
    ulong secs;
    struct casn time_casn, *tcasnp, *ch_casnp;
#ifdef FLOATS
    struct casn realobj;
#endif
    struct set_struct
	{
	long lth;
	uchar *c;
	struct casn *casnp;
	struct set_struct *nextp;
	} *sstp1, *sstp2, *sstp0, *tablep;

    if (casnp->level > 0 && (_go_up(casnp)->flags & ASN_OF_FLAG) &&
	!casnp->ptr) return _casn_obj_err(casnp, ASN_OF_BOUNDS_ERR);
    if ((lth = _check_filled(casnp, mode)) <= 0) return lth;
    if (casnp->tag == ASN_NOTYPE && (lth = _check_enum(&casnp)) <= 0)
        return lth;
    if (!(mode & ASN_READ)) to = buf;
    c = to;
    if ((casnp->flags & ASN_POINTER_FLAG) && !(casnp = casnp->ptr))
	return -1;
	// primitive if neither primitive-defined-by nor explicitly tagged
	// unless the type is ANY
    if (casnp->type == ASN_CHOICE && !(casnp->tag & ASN_CONSTRUCTED))
	{
	tcasnp = casnp;
	if (!(casnp = _find_filled_or_chosen(casnp, &num)))
            return _casn_obj_err(tcasnp, num);
	}
    if ((!(casnp->type & ASN_CONSTRUCTED) && !(casnp->tag & ASN_CONSTRUCTED)) ||
        !casnp->type ||
        (!(casnp->type & ASN_CONSTRUCTED) &&
        (casnp->flags & ASN_EXPLICIT_FLAG)))
        {
	lth = casnp->lth;
        tcasnp = casnp;  // unless changed bu time or real below
        if (casnp->type == ASN_BITSTRING && (casnp->flags & ASN_ENUM_FLAG))
	    {
	    i = 0;
	    for (b = &casnp->startp[casnp->lth]; --b > casnp->startp; )
		{
		for (bb = 1, i = 0; bb && !(bb & *b); bb <<= 1, i++);
		if (bb) break;
                }
	    i &= 7;
	    *casnp->startp = i;
	    lth = 1 + (b - casnp->startp);
	    }
	else if (casnp->type == ASN_UTCTIME || casnp->type == ASN_GENTIME)
	    {
            simple_constructor(&time_casn, (ushort)0, casnp->type);
	    if (read_casn_time(casnp, &secs) > 0 &&
	        (lth = write_casn_time(&time_casn, secs)) > 0)
		tcasnp = &time_casn;
	    else
                {
                clear_casn(&time_casn);
                return -1;
                }
	    }
#ifdef FLOATS
        else if (casnp->type == ASN_REAL)
	    {
	    double dbl;
	    int ttype = 0;
	    simple_constructor(&realobj, (short)0, ASN_REAL);
	    if ((casnp->startp[0] & 0x80) && (casnp->startp[0] & 0x30))
                ttype = 2;
	    else if (!(casnp->startp[0] & 0xC0) && (casnp->startp[0] & 0x3F)
                != 3) ttype = 10;
	    if (ttype)
	        {
	        if (read_casn_double(casnp, &dbl) < 0 ||
		    (lth = write_casn_double(&realobj, dbl, ttype)) < 0)
                    return -1;
	        tcasnp = &realobj;

	        }
	    }
#endif
        if ((mode & ASN_READ))
	    {
            memcpy(c, tcasnp->startp, lth);
	    if (tcasnp->type == ASN_BOOLEAN && *c) *c = 0xFF;
	    }
        if (tcasnp != casnp) clear_casn(tcasnp); // free stuff
        }
    else if (casnp->type == ASN_SET && (mode & ASN_READ))
	{
	num = 0;
	    // count how many there are in the SET
	if ((of = (casnp++)->flags & ASN_OF_FLAG))
    	    for (tcasnp = casnp; tcasnp && tcasnp->ptr; tcasnp = tcasnp->ptr,
                num++);
	else for (tcasnp = casnp; tcasnp; num++, tcasnp = _skip_casn(tcasnp, 1));
	    // prepare table of num + 1 entries for the SET
	tablep = (struct set_struct *)dbcalloc(num + 1, sizeof(struct set_struct));
	tablep[0].nextp = &tablep[1];
	    // for entries [1] to [num]
	for (tcasnp = casnp, sstp1 = &tablep[i = 1]; i <= num; )
	    {   // if error in it, return
	    if ((sstp1->lth = _encodesize(tcasnp, sstp1->c, 0)) < 0)
		{
		_free_it(tablep);
		return sstp1->lth;
		}
	    if (sstp1->lth)     // if not empty, fill it in
		{
    	        sstp1->c = dbcalloc(1, sstp1->lth + 1);
    	        sstp1->casnp = tcasnp;
    	        sstp1->nextp = &sstp1[1];
   	        _encodesize(tcasnp, (sstp1++)->c, ASN_READ);
		i++;
		}
	    else num--;     // empty. skip it
	    if (of) tcasnp = tcasnp->ptr;
	    else tcasnp = _skip_casn(tcasnp, 1);
	    }
	tablep[num].nextp = (struct set_struct *)0;  // unlink last one
		 // do bubble sort
	for (sstp0 = tablep, sstp1 = sstp0->nextp, i = 1; i < num; )
	    {
	    sstp2 = sstp1->nextp;
	    lth = (sstp1->lth < sstp2->lth)? sstp1->lth: sstp2->lth;
	    if (memcmp(sstp1->c, sstp2->c, lth + 1) > 0)
		{           // swap by changing links
		sstp1->nextp = sstp2->nextp;
		sstp2->nextp = sstp1;
		sstp0->nextp = sstp2;
		i = 1;      // go back to start
		sstp1 = (sstp0 = tablep)->nextp;
		}
	    else
		{
		sstp0 = sstp1;
		sstp1 = sstp2;
                i++;
		}
	    }
	for (lth = 0, sstp1 = tablep->nextp; num--; sstp1 = sstp1->nextp)
	    {
	    memcpy(c, sstp1->c, (i = sstp1->lth));
	    _free_it(sstp1->c);
	    c += i;
	    lth += i;
	    }
	_free_it((uchar *)tablep);
        }
    else
        {
    	lth = 0;
        if (casnp->tag == ASN_BITSTRING &&  // bit string defined by
				    // that is real
	    (ch_casnp = _find_chosen(casnp)) && ch_casnp->type != ASN_NOTASN1)
	    {
            lth++;
	    *c++ = 0;
	    }
        if ((casnp->flags & ASN_OF_FLAG))
            {
            for (tcasnp = &casnp[1], num = 1; tcasnp->ptr;
                tcasnp = tcasnp->ptr, num++)
                {
                if ((i = _encodesize(tcasnp, c, mode)) < 0)
		    {
		    _stuff_num(num);
                    _stuff_string(casnp);
                    return i - lth;
		    }
                lth += i;
                c += i;
                }
            }
        else
            {
            ch_casnp = (struct casn *)0;
	    if (casnp->type >= ASN_CHOICE)
		{
		ch_casnp = casnp;
		if (casnp->type == ASN_CHOICE && casnp->tag < ASN_CHOICE)
                    casnp = _find_filled(ch_casnp);
    		else if ((casnp->flags & ASN_DEFINED_FLAG))
                    casnp = _find_chosen(ch_casnp);
		if (!casnp)
                    return -lth + _casn_obj_err(ch_casnp, ASN_MATCH_ERR);
		}	  // not for explicitly tagged primitives
            else if (!(casnp->type & ASN_CONSTRUCTED) &&
                (casnp->flags & ASN_EXPLICIT_FLAG));
            else casnp++;
	    i = 0;
            do
                {
                if ((i = _encodesize(casnp, c, mode)) < 0) return i - lth;
                lth += i;
                if ((mode & ASN_READ)) c += i;     // if chosen, don't go further
                if ((casnp->flags & (ASN_LAST_FLAG | ASN_CHOSEN_FLAG))) break;
	        if (ch_casnp) return lth;
                casnp = _skip_casn(casnp, 1);
		}
            while(casnp);
            }
        }
    return lth;
    }

int _readvsize(struct casn *casnp, uchar *to, int mode)
    {      // handles default cases at level above _readsize()
    int ansr, tmp;
    struct casn *tcasnp;
    ushort flags = casnp->flags & (ASN_FILLED_FLAG | ASN_DEFAULT_FLAG);
    uchar *c;

    if (_clear_error(casnp) < 0) return -1;
    tcasnp = (struct casn *)0;
    if (casnp->type == ASN_CHOICE)
	{
        if (!(tcasnp = _find_filled_or_chosen(casnp, &ansr)))
    	    return _casn_obj_err(casnp, ansr);
	casnp = tcasnp;
	}           // is it (or a CHOICE above it) an empty default?
    if ((casnp->flags & (ASN_FILLED_FLAG | ASN_DEFAULT_FLAG)) ==
        ASN_DEFAULT_FLAG || (tcasnp && flags == ASN_DEFAULT_FLAG))
	{
        if (casnp->type == ASN_BOOLEAN)
	    {
            if ((casnp->min & BOOL_DEFINED))
    	        *to = (casnp->min & BOOL_DEFINED_VAL)? 0xFF: 0;
            else *to = (casnp->min & BOOL_DEFAULT)? 0xFF: 0;
	    return 1;
	    }
	else if (casnp->type == ASN_INTEGER || casnp->type == ASN_ENUMERATED)
	    {
   	    tmp = ansr = (int)tcasnp->ptr;
		// how big?
    	    if (ansr < 0) ansr = -ansr;
    	    for (c = to; ansr; ansr >>= 8, c++);
		// fill it in
	    for (ansr = c - to; --c >= to; *c = (tmp & 0xFF), tmp >>= 8);
	    return ansr;
	    }
	else return 0;
	}
    if ((ansr = _readsize(casnp, to, mode)) > 0 &&
        // pure read of bit-string-defined-by
        casnp->type == (ASN_CHOICE | ASN_BITSTRING) && ansr > 0)
        memcpy(to, &to[1], --ansr);   // shift to left 1 byte
    return ansr;
    }

int _set_all_lths(uchar *top, uchar *tag_endp, uchar *val_endp, int mode)
    {
    ulong tag;
    uchar *c = top;
    int lth;

    tag = _get_tag(&c);
    c++;    // at end of tag-lth;
    if (c < tag_endp) lth = _set_all_lths(c, tag_endp, val_endp, mode);
    else lth = 0;
    val_endp += lth;
    lth += _set_casn_lth(top, val_endp, mode);
    return lth;
    }

int _set_casn_lth(uchar *s, uchar *e, int mode)
    {
    uchar *c;
    ulong lth;
    int fwd;

                                                                    /* step 1 */
    if ((*s++ & 0x1F) == 0x1F) while ((*s & 0x80)) s++;
    s++;
    lth = e - s;

    fwd = _calc_lth_lth(lth);
    if (!(mode & ASN_READ)) return fwd;
    if (!fwd) s[-1] = lth;
    else                    /* expand for correct size of lth field */
        {
        for (c = e, e += fwd; c > s; *(--e) = *(--c));
        _put_asn_lth(e, lth);
        }
    return fwd;
    }

struct casn *_skip_casn(struct casn *casnp, int num)
    {
    struct casn *tcasnp;

    if (!num) return casnp;
    else if (num > 0)
        {
        if ((casnp->flags & ASN_LAST_FLAG)) return (struct casn *)0;
        for (tcasnp = &casnp[1]; num || (tcasnp->level > casnp->level &&
            !(tcasnp->flags & ASN_LAST_FLAG)); tcasnp++)
            {
            if (tcasnp->level < casnp->level) return (struct casn *)0;
            if (tcasnp->level == casnp->level && !(--num)) break;
            }
        if (!(tcasnp->flags | ASN_LAST_FLAG)) tcasnp = (struct casn *)0;
        }
    else
        {
        for (tcasnp = &casnp[-1]; num || tcasnp->level > tcasnp->level; tcasnp--)
            {
            if (tcasnp->level == casnp->level && !(++num)) break;
            else if (tcasnp->level < casnp->level) return (struct casn *)0;
            }
        }
    return tcasnp;
    }

void _stuff_num(int count)
    {
    char *a, *b, *c;

    if ((c = casn_err_struct.asn_map_string))
	{
	while(*c) c++;
        c = (char *)dbcalloc(1, (c - casn_err_struct.asn_map_string) + 8);
	}
    else c = (char *)dbcalloc(1, 8);
    a = c;
    c = _putd(c, count);
    *c++ = '.';
    for (b = casn_err_struct.asn_map_string; b && *b; *c++ = *b++);
    _free_it(casn_err_struct.asn_map_string);
    casn_err_struct.asn_map_string = a;
    }

void _stuff_ofs(struct casn *casnp, int num_ofs)
    {
    _stuff_num(num_ofs);
		// now go on up unless this is in an OF
    if (casnp->level) _stuff_string(casnp);
    }

void _stuff_string(struct casn *casnp)
    {
    struct casn *tcasnp, *ucasnp;
    int count;

#ifdef ASN_VERBOSE
    int lth;
    uchar *c, lbuf[10];
    char *b;

    memset(lbuf, 0, 16);
    c = lbuf;
    if (casnp->type == ASN_CHOICE) memcpy(lbuf, "cho", 3);
    else if (casnp->type == ASN_ANY) memcpy(lbuf, "any", 3);
    else
        {
        c += _dump_tag(casnp->type, lbuf, 0, 0, 1);
        *(--c) = 0;
        }
    if (c == lbuf) c += 3;
    if ((casnp->flags & ASN_OF_FLAG))
        {
        if (casnp->type == ASN_SEQUENCE) memcpy(lbuf, "sqf", 3);
        else memcpy(lbuf, "stf", 3);
        }
    if (casnp->type != casnp->tag)
        {
        *c++ = '(';
        *c = (casnp->tag >> 4) + '0';
        if (*c > '9') *c += 7;
        *(++c) = (casnp->tag & 0xF) + '0';
        if (*c > '9') *c += 7;
        c++;
        *c++ = ')';
        }
    lth = (c - lbuf);
    if (casn_err_struct.asn_map_string)
        {
        for (b = casn_err_struct.asn_map_string; *b; b++);
        count = b - casn_err_struct.asn_map_string;
        }
    else count = 0;
    b = (char *)dbcalloc(1, sizeof(lbuf) + count);
    memcpy(b, (char *)lbuf, lth);
    if (count) memcpy(&b[lth], casn_err_struct.asn_map_string, count);
    _free_it(casn_err_struct.asn_map_string);
    casn_err_struct.asn_map_string = b;
#endif
    if (casnp && (ucasnp = _go_up(casnp)))
	{
        for (count = 1, tcasnp = &ucasnp[1]; tcasnp && tcasnp != casnp; count++,
    	    tcasnp = _skip_casn(tcasnp, 1));
        _stuff_num(count);
        _stuff_string(ucasnp);
	}
    }

int _table_op(struct casn *casnp)
    {
    struct casn *tcasnp, *where_casnp;
    int num, tmp, err;

    where_casnp = casnp->ptr;
    for (num = 0, tmp = where_casnp->lth, tcasnp = &where_casnp[1]; tmp--;
        num++, tcasnp++)
	{
	if ((tcasnp->lth == casnp->lth &&
            !memcmp(tcasnp->startp, casnp->startp, tcasnp->lth)) ||
            (tcasnp->lth == 2 && *tcasnp->startp == 0xFF &&  // catch-all
	    tcasnp->startp[1] == 0xFF)) break;
	}
    err = 0;
    if (tmp < 0) err = ASN_DEFINER_ERR;
        /* now mark the chosen one(s) */
    else if (!_mark_definees(casnp, where_casnp->startp, num))
        err = ASN_DEFINED_ERR;
    if (err) return _casn_obj_err(casnp, err);
    return 1;
    }

int _write_casn(struct casn *casnp, uchar *c, int lth)
    {
    int num, err, tmp, has_indef = 0;
    uchar *b, mask;
    ulong val;
    struct casn *tcasnp;

    err = 0;
    if ((casnp->type & ASN_CONSTRUCTED) && casnp->tag < ASN_CHOICE)
	{
	if ((casnp->flags & ASN_OF_FLAG) && casnp[1].ptr)
            casnp[1].ptr = _clear_of(casnp[1].ptr);
	if (!lth)
	    {
	    if (casnp->min) return _casn_obj_err(casnp, ASN_OF_BOUNDS_ERR);
	    if ((err = _fill_upward(casnp, ASN_FILLED_FLAG)) < 0)
                return _casn_obj_err(casnp, -err);
	    return 0;
	    }
        return _match_casn(&casnp[1], c, lth, (casnp->flags & ASN_OF_FLAG),
               (ushort)1, 
               ((casnp->flags & ASN_OF_FLAG))? casnp: (struct casn *)0,
               &has_indef);
	}
    if (casnp->type == ASN_CHOICE)  // can't be defined-by here
	{
	if (casnp[1].type > sizeof(mask_table) ||
	    !mask_table[casnp[1].type]) err = ASN_CHOICE_ERR;
	else
	    {             // what's the most elaborate character
	    for (val = 0xFF, b = c, tmp = lth; tmp--;
                val &= (char_table[*b++]));
		// have we an option for it?
            for (tcasnp = &casnp[1]; tcasnp &&
              tcasnp->type < sizeof(mask_table) &&
              !(mask_table[tcasnp->type] & val);
              tcasnp = _skip_casn(tcasnp, 1));
	    if (tmp >= 0 || !tcasnp) err = ASN_NO_CHOICE_ERR;
	    }
	if (err) return _casn_obj_err(casnp, err);
	casnp = tcasnp;
	}
    tmp = _csize(casnp, c, lth); // tmp is 'byte' count
    if (casnp->type == ASN_NONE) err = ASN_NONE_ERR;
    else if ((casnp->type == ASN_INTEGER && lth > 1 &&
        ((!*c && !(c[1] & 0x80)) ||
        (*c == 0xFF && (c[1] & 0x80))))) err = ASN_CODING_ERR;
    else if (casnp->type == ASN_NULL && lth) err = ASN_LENGTH_ERR;
    else if (casnp->type == ASN_UTCTIME)
	{
	if (_utctime_to_ulong(&val, (char *)c, lth) < 0)
            err = ASN_TIME_ERR;
	}
    else if (casnp->type == ASN_GENTIME)
	{
	if (_gentime_to_ulong(&val, (char *)c, lth) < 0)
            err = ASN_TIME_ERR;
	}
    else if (!(casnp->flags & ASN_RANGE_FLAG) && casnp->max &&
        (tmp > casnp->max || tmp < casnp->min)) err = ASN_BOUNDS_ERR;
    else if ((casnp->flags & ASN_RANGE_FLAG))
	{
	if (lth > 4) err = ASN_BOUNDS_ERR;
	else if (casnp->min != casnp->max)
	    {
	    for (b = c, num = 0; b < &c[lth]; num = (num << 8) + (int)*b++);
	    if (num < casnp->min || num > casnp->max) err = ASN_BOUNDS_ERR;
            }
	}
    else 
      {
      tmp = -1;
      if (casnp->type == ASN_IA5_STRING) 
	for (b = c, tmp = lth; tmp-- && !(*b & 0x80); b++);
      else if (casnp->type < sizeof(mask_table))
        { 
        mask = mask_table[casnp->type];
        if (mask)
          for (b = c, tmp = lth; tmp-- && (char_table[*b] & mask); b++);
        }
      if (tmp >= 0) return _casn_obj_err(casnp, ASN_MASK_ERR) - tmp;
      }
    if (err) return _casn_obj_err(casnp, err);
    casnp->flags &= ~(ASN_FILLED_FLAG);
    if (casnp->startp) casnp->startp = _free_it(casnp->startp);
    casnp->startp = (uchar *)dbcalloc(1, (casnp->lth = lth));
    memcpy(casnp->startp, c, casnp->lth);
	    // fill up to top
    if ((err = _fill_upward(casnp, ASN_FILLED_FLAG)) < 0)
        return _casn_obj_err(casnp, -err);
    if ((casnp->flags & ASN_TABLE_FLAG) && _table_op(casnp) < 0) return -1;
    return casnp->lth;
    }

int _write_enum(struct casn *casnp)
    {
    struct casn *tcasnp;

    if (!(tcasnp = _go_up(casnp)) || !(tcasnp->flags & ASN_ENUM_FLAG) ||
	    tcasnp->type != casnp->type) return -1;
	return _write_casn(tcasnp, casnp->startp, casnp->lth);
    }

int _write_objid(struct casn *casnp, char *from)
    {
    char *c = from;
    long tmp, val;
    int i, siz;
    uchar *a, *b, *buf, *e;

    _clear_casn(casnp, ~(ASN_FILLED_FLAG));
    for (e = (uchar *)from, tmp = 0; *e; tmp++, e++);
    casnp->startp = buf = (uchar *)dbcalloc(1, tmp);  // bigger than needed
    if (casnp->type == ASN_OBJ_ID)
	{
        for (val = 0; c < (char *)e && *c && *c != '.';
            val = (val * 10) + *c++ - '0');
        val *= 40;
        if (c >= (char *)e) return _casn_obj_err(casnp, ASN_BOUNDS_ERR);
        for (c++, tmp = 0; c < (char *)e && *c && *c != '.';
            tmp = (tmp * 10) + *c++ - '0');
        val += tmp;
        for (tmp = val, siz = 0; tmp; siz++) tmp >>= 7;/* size of first field */
				        /* put it into result */
        for (i = siz, tmp = val, b = &buf[siz]; siz--; val >>= 7)
            *(--b) = (unsigned char)(val & 0x7F) | ((tmp != val)? 0x80: 0);
	if (*c == '.') c++;
	}
    else i = 0;
    if (*c) for (; *c; c++)                       /* now do next fields */
        {
        for (val = 0; *c && *c != '.'; val = (val * 10) + *c++ - '0');
        if (!val) siz = 1;
        else for (tmp = val, siz = 0; tmp; siz++) tmp >>= 7;
        for(a = &buf[i], i += siz, tmp = val, e = b = &a[siz]; siz--; val >>= 7)
    	    *(--b) = (unsigned char)(val & 0x7F) | ((tmp != val)? 0x80: 0);
        if (!*c) break;
        }
    casnp->lth = (e - buf);
    if ((i = _fill_upward(casnp, ASN_FILLED_FLAG)) < 0)
        return _casn_obj_err(casnp, -i);
    if ((casnp->flags & ASN_TABLE_FLAG) && _table_op(casnp) < 0) return -1;
    return casnp->lth;
    }

