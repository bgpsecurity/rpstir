/* $Id$ */
/* */
/*****************************************************************************
File:     casn_copy_diff.c
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
 * Copyright (C) BBN Technologies 2004-2010.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK *****
*****************************************************************************/
#include "casn.h"
char casn_copy_diff_sfcsid[] = "@(#)casn_copy_diff.c 864P";

extern void _clear_casn(struct casn *, ushort);

extern struct casn *_find_chosen(struct casn *casnp),
            *_dup_casn(struct casn *casnp),
            *_find_filled(struct casn *casnp),
            *_find_filled_or_chosen(struct casn *casnp, int *errp),
            *_find_flag(struct casn *casnp, int flag),
            *_find_tag(struct casn *casnp, ulong tag),
            *_go_up(struct casn *casnp),
            *_skip_casn(struct casn *casnp, int num);

extern int _casn_obj_err(struct casn *, int),
    _calc_lth_lth(int),
    _check_filled(struct casn *, int),
    _clear_error(struct casn *),
    _encode_tag_lth(uchar *to, struct casn **casnpp),
    _fill_upward(struct casn *casnp, int val);

int _copy_casn(struct casn *to_casnp, struct casn *fr_casnp, int level),
    _diff_casn(struct casn *casnp1, struct casn *casnp2, int mode);

int copy_casn(struct casn *to_casnp, struct casn *fr_casnp)
    {
    if (to_casnp->level > 0 && (_go_up(to_casnp)->flags & ASN_OF_FLAG) &&
        !to_casnp->ptr)
        return _casn_obj_err(to_casnp, ASN_OF_BOUNDS_ERR);
    if (_clear_error(to_casnp) < 0 || _clear_error(fr_casnp) < 0) return -1;
    if (!(fr_casnp->flags & ASN_FILLED_FLAG))
      return _casn_obj_err(fr_casnp, ASN_EMPTY_ERR);
    _clear_casn(to_casnp, ~(ASN_FILLED_FLAG));
    return _copy_casn(to_casnp, fr_casnp, 0);
    }

int diff_casn(struct casn *casnp1, struct casn *casnp2)
    {
    int diff, neg;

    if (_clear_error(casnp1) < 0 || _clear_error(casnp2) < 0) return -1;
    if ((casnp1->type != casnp2->type && casnp2->type != ASN_NOTASN1 &&
        !(casnp1->flags & ASN_ENUM_FLAG)) ||
        !(casnp1->flags & ASN_FILLED_FLAG) || !(casnp2->flags & ASN_FILLED_FLAG))
        return -2;
    if (casnp1->type == ASN_INTEGER || casnp1->type == ASN_ENUMERATED ||
        casnp1->type == ASN_BOOLEAN)
	{
	if (!casnp1->startp || !casnp2->startp) return -2;
	if (casnp1->type == ASN_INTEGER)
	    {
    	    neg = *casnp1->startp & 0x80;
    	    diff = *casnp2->startp & 0x80;
    	    if (neg && !diff) return -1;
    	    if (!neg && diff) return 1;
	    }
	else neg = 0;
	if (casnp1->lth > casnp2->lth) diff = 1;
	else if (casnp1->lth < casnp2->lth) diff = -1;
	else diff = memcmp(casnp1->startp, casnp2->startp, casnp1->lth);
	if (neg) diff = - diff;
	}
    else if (!(casnp1->type & ASN_CONSTRUCTED))
	diff = _diff_casn(casnp1, casnp2, 0);
    else for (casnp1++, casnp2++; casnp1 && casnp2;
        casnp1 = _skip_casn(casnp1, 1),
        casnp2 = _skip_casn(casnp2, 1))
	{
	if ((diff = _diff_casn(casnp1, casnp2, 1))) break;
	}
    return diff;
    }

int _copy_casn(struct casn *to_casnp, struct casn *fr_casnp, int level)
    {
/**
Procedure:
1. Return error if types and "OF" flags don't match
   IF the from side isn't filled in and has no error, return 0
   WHILE copying from a CHOICE OR a DEFINED BY
	Find the filled or chosen member on the from side
        IF the from item is empty
            IF the CHOICE OR the member itself is optional OR has a defeult
		Return zero
	    Return mandatory error
	IF it's a DEFINED BY, find the chosen member on the to side
	ELSE find the matching tag on the to side
   IF error, return error
2. IF the to member is a pointer item
	Make its pointed-to item
	Move the from pointer to its pointed-to item
3. IF the from member is empty AND has no default
	IF it's optional, return zero
	Return mandatory error
4. IF copying from an OF
	IF it's a present but empty OF, fill the to item
	ELSE FOR each memeber of the OF
	    Make a new member on the to side
	    Copy to it, counting results
   ELSE IF it's constructed
	IF copying to something other than an ANY
	    IF the subtags don't match, return error
	    Copy all the members on the from side
	    IF the constructed item is present but empty, fill the to item
	ELSE IF it has some contents, write those to the to side
5. Figure how much we've done so far
   Adjust that for the length of the length field
   Add the length of the tag
   Return the count
**/

    struct casn *tcasnp;
    int ansr, did, err, flags, num;
    uchar locbuf[8];
						    // step 1
    ansr = did = err = 0;
    if ((to_casnp->type != ASN_ANY && (fr_casnp->type != to_casnp->type ||
	(level && fr_casnp->tag != to_casnp->tag))) ||
	(fr_casnp->flags & ASN_OF_FLAG) != (to_casnp->flags & ASN_OF_FLAG))
        return _casn_obj_err(fr_casnp, ASN_MATCH_ERR);
    if (!_check_filled(fr_casnp, 0)) return 0;
    for (err = 0; !err && fr_casnp->type >= ASN_CHOICE; )
	{
	if ((fr_casnp = _find_filled_or_chosen((tcasnp = fr_casnp), &err)))
	    {
	    if (!err && (to_casnp->flags & ASN_DEFINED_FLAG))
    		{
                if (!(to_casnp = _find_chosen((tcasnp = to_casnp))))
                    err = ASN_DEFINED_ERR;
                if (to_casnp->type == ASN_ANY) to_casnp->tag = fr_casnp->tag;
    		}
            else if (!(to_casnp = _find_tag(&(tcasnp = to_casnp)[1], fr_casnp->tag)))
    		err = ASN_MATCH_ERR;
	    }
	if (fr_casnp && !(fr_casnp->flags & ASN_FILLED_FLAG))
	    {
	    if ((tcasnp->flags & (ASN_OPTIONAL_FLAG | ASN_DEFAULT_FLAG)) ||
	        (fr_casnp->flags & (ASN_OPTIONAL_FLAG | ASN_DEFAULT_FLAG)))
    	        return 0;
	    err = ASN_MANDATORY_ERR;
	    }
	}
    if (err) return _casn_obj_err(tcasnp, err);
						    // step 2
    tcasnp = fr_casnp;
    if ((to_casnp->flags & ASN_POINTER_FLAG))
	{
        to_casnp = _dup_casn(to_casnp);
	fr_casnp = fr_casnp->ptr;
	}
						    // step 3
    if (!(fr_casnp->flags & (ASN_FILLED_FLAG | ASN_DEFAULT_FLAG)))
	{
	if ((fr_casnp->flags & ASN_OPTIONAL_FLAG)) return 0;
	return _casn_obj_err(tcasnp, ASN_MANDATORY_ERR);
	}
						    // step 4
    if ((fr_casnp->flags & ASN_OF_FLAG))
        {
	if ((fr_casnp->flags & ASN_FILLED_FLAG) && !fr_casnp[1].ptr)
            {
            if ((err = _fill_upward(to_casnp, ASN_FILLED_FLAG)) < 0)
               return _casn_obj_err(to_casnp, -err);
            }
	else
	    {
            for (fr_casnp++, tcasnp = &to_casnp[1], num = 0; fr_casnp->ptr;
                fr_casnp = fr_casnp->ptr, num++)
                {
                if (!(tcasnp = inject_casn(to_casnp, num))) return -did;
                if ((ansr = _copy_casn(tcasnp, fr_casnp, level)) < 0)
                    return ansr - did;
    	        did += ansr;
                }
	    ansr = 0;
            }
	}
    else if ((fr_casnp->type & ASN_CONSTRUCTED))
	{
	flags = fr_casnp->flags;
        if (to_casnp->type != ASN_ANY)
	    {
	    level++;
	    if ((++fr_casnp)->tag != (++to_casnp)->tag &&
                to_casnp->type != ASN_ANY)
                return _casn_obj_err(to_casnp, ASN_MATCH_ERR);
	    while (fr_casnp)
                {
                if ((ansr = _copy_casn(to_casnp, fr_casnp, level)) < 0)
		    return ansr - did;
		did += ansr;
                if ((fr_casnp = _skip_casn(fr_casnp, 1)) &&
                    !(tcasnp = _skip_casn(to_casnp, 1)))
                    return _casn_obj_err(to_casnp, ASN_MATCH_ERR) - did;
	        to_casnp = tcasnp;
                }
	    if (!did && (flags & ASN_FILLED_FLAG) &&
		(err = _fill_upward(to_casnp, ASN_FILLED_FLAG)) < 0)
                return _casn_obj_err(to_casnp, -err);
	    did -= ansr;
	    }
	else
	    {
	    if ((ansr = vsize_casn(fr_casnp)) < 0) return -1;
	    to_casnp->startp = calloc(1, ansr);
	    read_casn(fr_casnp, to_casnp->startp);
	    to_casnp->lth = ansr;
	    to_casnp->tag = fr_casnp->tag;
	    if ((err = _fill_upward(to_casnp, ASN_FILLED_FLAG)) < 0)
                return _casn_obj_err(to_casnp, -err);
	    }
	}
    else if (fr_casnp->startp)  // might be empty because of default
	{
	if ((ansr = _write_casn(to_casnp, fr_casnp->startp, fr_casnp->lth))
	    < 0) return ansr - did;
	}
							// step 5
    did += ansr;
    did += _calc_lth_lth(did);
    tcasnp = to_casnp;
    did += _encode_tag_lth(locbuf, &tcasnp);
    return did;
    }

int _diff_casn(struct casn *casnp1, struct casn *casnp2, int mode)
    {   // mode = 0 if at top level; mode = 1 if at lower level
    int diff, lth, lth1, lth2;

    lth1 = (casnp1->flags & ASN_FILLED_FLAG);
    lth2 = (casnp2->flags & ASN_FILLED_FLAG);
    if (!lth1 || !lth2)
        {
        if (!lth1 && !lth2) return 0;
        return (!lth1)? -1: 1;
        }
    while ((casnp1->type == ASN_CHOICE && (casnp1 = _find_filled(casnp1))) ||
	(casnp2->type == ASN_CHOICE && (casnp2 = _find_filled(casnp2))));
    if (!casnp1 || !casnp2) return -2;
    if (!(casnp1->type & ASN_CONSTRUCTED))
	{
        if ((lth1 = vsize_casn(casnp1)) < 0 || (lth2 = vsize_casn(casnp2)) < 0)
    	    return -2;
	if (!(diff = (mode)? casnp1->tag - casnp2->tag:
            casnp1->type - casnp2->type) && !(diff = lth1 - lth2))
	    {
            lth = (lth1 < lth2)? lth1: lth2;    // get the shorter
            if (lth >= 0)
                {
                diff = memcmp(casnp1->startp, casnp2->startp, lth);
    	        if (!diff)
                    {
                    if (lth1 > lth) diff = 1;
                    else if (lth2 > lth) diff = -1;
                    }
                }
    	    }
	if (diff > 1) diff = 1;
	else if (diff < -1) diff = -1;
	}
    else for (casnp1++, casnp2++; casnp1 && casnp2;
        casnp1 = _skip_casn(casnp1, 1),
        casnp2 = _skip_casn(casnp2, 1))
	{
	if ((diff = _diff_casn(casnp1, casnp2, 1))) break;
	}
    return diff;
    }

