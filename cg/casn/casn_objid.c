/* $Id$ */
/*****************************************************************************
File:     casn_objid.c
Contents: Basic functions for ASN.1 objects.
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

COPYRIGHT 2004 BBN Systems and Technologies
10 Moulton St.
Cambridge, Ma. 02138
617-873-3000
*****************************************************************************/

char casn_objid_sfcsid[] = "@(#)casn_objid.c 866P";
#include "casn.h"

#define ASN_READ 1          // modes for encode & read

extern int _casn_obj_err(struct casn *, int),
    _check_enum(struct casn **casnpp),
    _clear_error(struct casn *),
    _write_enum(struct casn *casnp),
    _write_objid(struct casn *casnp, char *from);

extern char *_putd(char *to, long val);

extern void *_free_it(void *);

int _readsize_objid(struct casn *casnp, char *to, int mode);

int diff_objid(struct casn *casnp, char *objid)
    {
    int ansr, lth, lth2;
    char *c;

    for (c = objid; *c; c++);
    lth2 = c - objid + 1;    // include terminal null, as read_objid does
    if ((lth = vsize_objid(casnp)) <= 0) return -2;
    c = dbcalloc(1, lth);
    read_objid(casnp, c);
    if (lth < lth2) ansr = lth;
    else ansr = lth2;
    if ((ansr = memcmp(c, objid, ansr)) == 0)
	{
	if (lth2 > lth) ansr = 1;
	else if (lth < lth2) ansr = -1;
	}
    else if (ansr > 0) ansr = 1;
    else ansr = -1;
    _free_it(c);
    return ansr;
    }

int read_objid(struct casn *casnp, char *to)
    {
    if (_clear_error(casnp) < 0) return -1;
    if (casnp->type != ASN_OBJ_ID && casnp->type != ASN_RELATIVE_OID)
        return _casn_obj_err(casnp, ASN_TYPE_ERR);
    return _readsize_objid(casnp, to, 1);
    }

int vsize_objid(struct casn *casnp)
    {
    char buf[16];

    if (_clear_error(casnp) < 0) return -1;
    if (casnp->type != ASN_OBJ_ID && casnp->type != ASN_RELATIVE_OID)
        return _casn_obj_err(casnp, ASN_TYPE_ERR);
    return _readsize_objid(casnp, buf, 0);
    }

int write_objid(struct casn *casnp, char *from)
    {

    if (_clear_error(casnp) < 0) return -1;
    if (casnp->type != ASN_OBJ_ID && casnp->type != ASN_RELATIVE_OID) return -1;
    if (casnp->tag == ASN_NOTYPE) return _write_enum(casnp);
    return _write_objid(casnp, from);
    }

// If there's no OID and no error, return 0. If there's an error, return
// negative. If there is an OID, it includes a trailing NULL byte in the
// length and optionally the buffer.
int _readsize_objid(struct casn *casnp, char *to, int mode)
    {
    int lth;
    uchar *c = casnp->startp, *e = &c[casnp->lth];
    char *b;
    ulong val;

    b = to;
    lth = 0;
    if (casnp->tag == ASN_NOTYPE && (lth = _check_enum(&casnp)) <= 0)
        return lth;
    if (!casnp->lth) return 0;
    if (casnp->type == ASN_OBJ_ID ||                   // elements 1 & 2
	(casnp->type == ASN_ANY && casnp->tag == ASN_OBJ_ID))
	{   // have to allow tag for a mixed definer
        for (val = 0; c < e && (*c & 0x80); c++)
            {
            val = (val << 7) + (*c & 0x7F);
            }
        val = (val << 7) + *c++;
        b = _putd(to, (val < 120)? (val / 40): 2);
        *b++ = '.';
        b = _putd(b, (val < 120)? (val % 40): val - 80);
        if (!(mode & ASN_READ))
            {
            lth = b - to;
            b = to;
    	    }
	if (c < e) *b++ = '.';
	}
    while (c < e)
        {
        for (val = 0; (*c & 0x80); c++)
            {
            val = (val << 7) + (*c & 0x7F);
            }
        val = (val << 7) + *c++;
	b = _putd(b, val);
	if (c < e) *b++ = '.';
    	if (!(mode & ASN_READ))
            {
            lth += b - to;
            b = to;
    	    }
        }
    if ((mode & ASN_READ)) *b++ = 0;
    return (mode & ASN_READ)? (b - to): ++lth;
    }

