/* $Id$ */
/*****************************************************************************
File:     casn_bit.c
Contents: Functions to handle BIT STRING ASN.1 objects.
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

char casn_bit_sfcsid[] = "@(#)casn_bit.c 851P";
#include "casn.h"

extern struct casn *_go_up(struct casn *);
extern int _casn_obj_err(struct casn *, int),
    _clear_error(struct casn *),
    _fill_upward(struct casn *casnp, int val);

int read_casn_bit(struct casn *casnp)
    {
    struct casn *tcasnp;
    int bits, lth;

    if (_clear_error(casnp) < 0) return -1;
    if (casnp->tag != ASN_NOTYPE || !(tcasnp = _go_up(casnp)) ||
	tcasnp->type != ASN_BITSTRING) return _casn_obj_err(casnp, ASN_TYPE_ERR);
    bits = casnp->min;
    lth = 1 + (bits >> 3);    // which one wiil we read?
    bits &= 7;
    if (lth >= tcasnp->lth ||   // beyond what we have now?
        (lth - 1 == tcasnp->lth && (int)*tcasnp->startp + bits > 7))
	return 0;
    return (int)tcasnp->startp[lth] & (0x80 >> bits);
    }

int write_casn_bit(struct casn *casnp, int val) 
    {
/**
Function: Writes enumerated bit to higher BIT STRING
**/
    struct casn *tcasnp = _go_up(casnp);  // the BIT STRING
    int bits, lth;
    uchar *b, bb;

    if (_clear_error(casnp) < 0) return -1;
    if (casnp->tag != ASN_NOTYPE || !tcasnp || tcasnp->type != ASN_BITSTRING)
        return _casn_obj_err(casnp, ASN_TYPE_ERR);
    bits = casnp->min;
    lth = 2 + (bits >> 3);    // which one wiil we write?
    if (lth >= tcasnp->lth)    // beyond what we have now?
	{
	tcasnp->startp = (uchar *)realloc(tcasnp->startp, lth + 1);
        memset(&tcasnp->startp[tcasnp->lth], 0,  lth - tcasnp->lth);
	tcasnp->lth = lth;
	}
    b = &tcasnp->startp[lth - 1];
    bb = 0x80 >> (bits & 7);
    if (val) *b |= bb;
    else *b &= ~bb;
    if ((bits = _fill_upward(tcasnp, ASN_FILLED_FLAG)) < 0)
        return _casn_obj_err(tcasnp, -bits);
    return (val)? 1: 0;
    }

