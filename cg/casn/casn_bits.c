/* $Id$ */
/* */
/*****************************************************************************
File:     casn_bits.c
Contents: Functions to hanndle ASN.1 BIT STRING objects.
System:   Compact ASN development.
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
 * Copyright (C) BBN Technologies 2004-2007.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK *****
*****************************************************************************/

char casn_bits_sfcsid[] = "@(#)casn_bits.c 864P";
#include "casn.h"

extern struct casn *_go_up(struct casn *);
extern int _casn_obj_err(struct casn *, int),
	_clear_error(struct casn *),
        _fill_upward(struct casn *casnp, int val);
extern void *_free_it(void *);

int _readsize_bits(struct casn *casnp, uchar *to, int *shift, int mode)
    {
    int err;
    ushort box;
    uchar *b, *c, *e;

    if (_clear_error(casnp) < 0) return -1;
    err = 0;
    if (casnp->type != ASN_BITSTRING) err = ASN_TYPE_ERR;
    else if (!casnp->startp) err = ASN_MANDATORY_ERR;
    if (err) return _casn_obj_err(casnp, err);
    c = casnp->startp;
    if ((casnp->flags & ASN_ENUM_FLAG)) *shift = 0;
    else *shift = (int)*c;
    for (e = &c[casnp->lth], c++; --e > c && !*e; );
    if (*e) e++;
    for (err = box = 0, *(b = to) = 0; c < e; c++, err++)
	{
	box = *c << 8;
	box >>= *shift;
	*b |= (box >> 8);
	if (mode) b++;
	*b = box & 0xFF;
	}
    return err;
    }

int read_casn_bits(struct casn *casnp, uchar *to, int *shift)
    {
    return _readsize_bits(casnp, to, shift, 1);
    }

int vsize_casn_bits(struct casn *casnp)
    {
    int shift;
    uchar buf[4];

    return _readsize_bits(casnp, buf, &shift, 0);
    }

int write_casn_bits(struct casn *casnp, uchar *from, int lth, int shift)
    {
    uchar *c, *e;
    ushort box;
    int err = 0;

    if (_clear_error(casnp) < 0) return -1;
    if (casnp->type != ASN_BITSTRING) return _casn_obj_err(casnp, ASN_TYPE_ERR);
    _free_it(casnp->startp);
    c = casnp->startp = (uchar *)calloc(1, (casnp->lth = lth + 1));
    for (e = &from[lth]; from < e; from++)
	{
	box = (ushort)*from;   
	box <<= shift;           // first time top 8 bits are empty
	*c++ |= (box >> 8);
	*c = box & 0xFF;
	}
    *casnp->startp = (uchar)shift;
    if ((err = _fill_upward(casnp, ASN_FILLED_FLAG)) < 0)
        return _casn_obj_err(casnp, -err);
    return casnp->lth;
    }
