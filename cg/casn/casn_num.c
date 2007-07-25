/* $Id$ */
/* Apr 12 2007 854U  */
/* Apr 12 2007 GARDINER added test before fill_upward in write_casn_num */
/* Apr  6 2007 851U  */
/* Apr  6 2007 GARDINER changed fill_upward() */
/* Apr 21 2006 835U  */
/* Apr 21 2006 GARDINER fixed clearing */
/* Aug  5 2004 797U  */
/* Aug  5 2004 GARDINER fixed DEFAULT cases in read_casn_num() */
/* Jul 23 2004 787U  */
/* Jul 22 2004 GARDINER fixed */
/* Jul 14 2004 780U  */
/* Jul 14 2004 GARDINER changed clear_casn to _clear_casn */
/* Jun  8 2004 773U  */
/* Jun  8 2004 GARDINER put test for numm pointer into _clear_error() */
/* May 21 2004 764U  */
/* May 21 2004 GARDINER more fixes for asn_obj tests */
/* Apr 21 2004 761U  */
/* Apr 21 2004 GARDINER fixed for half of casn_obj testing */
/* Apr  1 2004 753U  */
/* Apr  1 2004 GARDINER added _fill_upward() */
/* Apr  1 2004 752U  */
/* Apr  1 2004 GARDINER fixed handling of negative integers */
/* Apr  1 2004 751U  */
/* Apr  1 2004 GARDINER fixed read_casn_num for 5-byte negative numbers */
/* Mar 31 2004 750U  */
/* Mar 31 2004 GARDINER fixed error treatment in read_casn_num */
/* Mar 25 2004 744U  */
/* Mar 25 2004 GARDINER fixed warnings; made val signed */
/* Mar 25 2004 743U  */
/* Mar 25 2004 GARDINER started */
/* */
/*****************************************************************************
File:     casn_num.c
Contents: Functions to handle numeris ASN.1 objects.
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

 ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Verison 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE RESTRICTED RIGHTS (JUNE 1987)
 * US government users are permitted restricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2004-2007.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK *****
*****************************************************************************/

char casn_num_sfcsid[] = "@(#)casn_num.c 854P";
#include "casn.h"

extern struct casn *_go_up(struct casn *);
extern void _clear_casn(struct casn *, ushort);

extern int _casn_obj_err(struct casn *, int),
    _check_filled(struct casn *casnp, int),
    _clear_error(struct casn *),
    _fill_upward(struct casn *, int),
    _write_casn(struct casn *casnp, uchar *c, int lth);

int _table_op(struct casn *casnp),
    _write_casn_num(struct casn *casnp, long val);

int diff_casn_num(struct casn *casnp, long val)
    {
    int neg, tmp;
    uchar *b, *e;

    if ((casnp->type != ASN_INTEGER && casnp->type != ASN_ENUMERATED) ||
        casnp->lth > sizeof(long) || !(casnp->flags & ASN_FILLED_FLAG)) 
        return _casn_obj_err(casnp, ASN_TYPE_ERR) - 1;
    if (casnp->type == ASN_INTEGER && (*casnp->startp & 0x80)) neg = 1;
    else neg = 0;
    e = &(b = casnp->startp)[casnp->lth];
    for (tmp = (*b++ & ~0x80); b < e; tmp = (tmp << 8) + *b++);
    if (neg) tmp = -tmp;
    if (val > tmp) return 1;
    else return (val == tmp)? 0: -1;
    }

int read_casn_num(struct casn *casnp, long *valp)
    {
    struct casn *tcasnp;
    int ansr, err = 0;
    uchar *c, buf[4];

    if (_clear_error(casnp) < 0) return -1;
    if (casnp->type == ASN_NOTYPE)
	{
	if (!(tcasnp = _go_up(casnp))) err = ASN_TYPE_ERR;
	}
    else tcasnp = casnp;
    if (!err)
	{
        if ((ansr = _check_filled(tcasnp, 1)) < 0 ||
            (!ansr && !(tcasnp->flags & ASN_DEFAULT_FLAG))) return ansr;
        if (tcasnp->type != ASN_INTEGER && tcasnp->type != ASN_ENUMERATED &&
            tcasnp->type != ASN_BOOLEAN)
    	    err = ASN_TYPE_ERR;
	else if (tcasnp->lth > sizeof(long) + 1 ||
	    (tcasnp->lth == sizeof(long) + 1 && *tcasnp->startp != 0xFF))
            err = ASN_LENGTH_ERR;
	}
    if (err) return _casn_obj_err(casnp, err);
		// if not filled but has default
    if ((tcasnp->flags & (ASN_FILLED_FLAG | ASN_DEFAULT_FLAG)) ==
        ASN_DEFAULT_FLAG)
	{
	if (tcasnp->type == ASN_BOOLEAN)
    	    {
    	    read_casn(tcasnp, buf);
	    *valp = buf[0];
	    return 1;
	    }
	*valp = (int)tcasnp->ptr;
	if ((ansr = *valp) < 0) ansr = -ansr;
	for (c = casnp->startp; ansr; ansr >>= 8, c++);
	}
    else
        {
        if ((*tcasnp->startp & 0x80) && tcasnp->type == ASN_INTEGER)
            *valp = -1;
        else *valp = 0;
        for (c = casnp->startp; c < &casnp->startp[casnp->lth];
            *valp = (*valp << 8) + (long)*c++);
	}
    return (c - casnp->startp);
    }

int write_casn_num(struct casn *casnp, long val)
    {
    struct casn *tcasnp;
    int ansr, err = 0;

    if (_clear_error(casnp) < 0) return -1;
    if (casnp->tag == ASN_NOTYPE)
	{
	if (!(tcasnp = _go_up(casnp)) || !(tcasnp->flags & ASN_ENUM_FLAG) ||
	    (tcasnp->type != ASN_INTEGER && tcasnp->type != ASN_ENUMERATED))
	    return -1;
	return _write_casn(tcasnp, casnp->startp, casnp->lth);	     
	}
    if ((casnp->type != ASN_INTEGER && casnp->type != ASN_ENUMERATED &&
        casnp->type != ASN_BOOLEAN) || (val < 0 && casnp->type != ASN_INTEGER))
	err = ASN_TYPE_ERR;
    else
	{
        ansr = _write_casn_num(casnp, val);
        if (casnp->max)
	    {
            if ((casnp->flags & ASN_RANGE_FLAG))
		{
                if (val > casnp->max || val < casnp->min) err = ASN_BOUNDS_ERR;
		}
	    else if (ansr < casnp->min || ansr > casnp->max)
                err = ASN_BOUNDS_ERR;
	    }
	}
    if (err)
	{
	_clear_casn(casnp, ~(ASN_FILLED_FLAG));
	return _casn_obj_err(casnp, err);
        }
    return ansr;
    }

int _write_casn_num(struct casn *casnp, long val)
    {
    long tmp;
    int err = 0, siz;
    uchar *c;
    struct casn *tcasnp;

    _clear_casn(casnp, ~(ASN_FILLED_FLAG)); // don't clear CHOSEN flag
    tmp = val;
    if (tmp > 0) for (siz = 1; tmp > 0x7F; siz++, tmp >>= 8);
    else for (siz = 1; tmp < -128; siz++, tmp >>= 8);
    casnp->startp = (uchar *)dbcalloc(1, siz + 1);
    for (c = &casnp->startp[siz]; val != 0 && val != -1;
        *(--c) = (val & 0xFF), val >>= 8);
    if (val < 0 && !*casnp->startp) *casnp->startp = 0xFF;
    casnp->lth = siz;
    tcasnp = _go_up(casnp);
    if (tcasnp && (tcasnp->flags & ASN_ENUM_FLAG) > 0) casnp->flags |= ASN_FILLED_FLAG;
    else if ((err = _fill_upward(casnp, ASN_FILLED_FLAG)) < 0)
        return _casn_obj_err(casnp, -err);
    if ((casnp->flags & ASN_TABLE_FLAG) && _table_op(casnp) < 0) return -1;
    return siz;
    }

