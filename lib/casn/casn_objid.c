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

#include "casn.h"
#include "casn_private.h"

// modes for encode & read
#define ASN_READ 1

extern char *
_putd(
    char *to,
    long val);

int
_readsize_objid(
    struct casn *casnp,
    char *to,
    int mode);

int diff_objid(
    struct casn *casnp,
    const char *objid)
{
    int ansr;
    int lth;
    int lth2;
    char *c;
    const char *c_const;

    for (c_const = objid; *c_const; c_const++);
    // include terminal null, as read_objid does
    lth2 = c_const - objid + 1;
    if ((lth = vsize_objid(casnp)) <= 0)
        return -2;
    c = dbcalloc(1, lth);
    /** @bug error code ignored without explanation */
    read_objid(casnp, c);
    if (lth < lth2)
        ansr = lth;
    else
        ansr = lth2;
    if ((ansr = memcmp(c, objid, ansr)) == 0)
    {
        if (lth2 > lth)
            ansr = 1;
        else if (lth < lth2)
            ansr = -1;
    }
    else if (ansr > 0)
        ansr = 1;
    else
        ansr = -1;
    _free_it(c);
    return ansr;
}

int read_objid(
    struct casn *casnp,
    char *to)
{
    if (_clear_error(casnp) < 0)
        return -1;
    if (casnp->type != ASN_OBJ_ID && casnp->type != ASN_RELATIVE_OID)
        return _casn_obj_err(casnp, ASN_TYPE_ERR);
    return _readsize_objid(casnp, to, 1);
}

int vsize_objid(
    struct casn *casnp)
{
    /** @bug magic number */
    char buf[16];

    if (_clear_error(casnp) < 0)
        return -1;
    if (casnp->type != ASN_OBJ_ID && casnp->type != ASN_RELATIVE_OID)
        return _casn_obj_err(casnp, ASN_TYPE_ERR);
    return _readsize_objid(casnp, buf, 0);
}

int write_objid(
    struct casn *casnp,
    const char *from)
{

    if (_clear_error(casnp) < 0)
        return -1;
    if (casnp->type != ASN_OBJ_ID && casnp->type != ASN_RELATIVE_OID)
        return -1;
    if (casnp->tag == ASN_NOTYPE)
        return _write_enum(casnp);
    return _write_objid(casnp, from);
}

// If there's no OID and no error, return 0. If there's an error, return
// negative. If there is an OID, it includes a trailing NULL byte in the
// length and optionally the buffer.
int _readsize_objid(
    struct casn *casnp,
    char *to,
    int mode)
{
    int lth = 0;
    uchar *c = casnp->startp;
    uchar *e = &c[casnp->lth];
    char *b = to;
    ulong val;

    if (casnp->tag == ASN_NOTYPE && (lth = _check_enum(&casnp)) <= 0)
        return lth;
    if (!casnp->lth)
        return 0;
    // elements 1 & 2
    if (casnp->type == ASN_OBJ_ID ||
        // have to allow tag for a mixed definer
        (casnp->type == ASN_ANY && casnp->tag == ASN_OBJ_ID))
    {
        /**
         * @bug
         *     This logic does not properly handle OID components that
         *     are too big to fit in an unsigned long
         */
        /**
         * @bug
         *     BER and DER prohibit leading bytes equal to 0x80.  This
         *     logic ignores them.  Should it error out somehow?
         */
        for (val = 0; c < e && (*c & 0x80); c++)
        {
            val = (val << 7) + (*c & 0x7F);
        }
        /** @bug invalid read if c == e */
        val = (val << 7) + *c++;
        /** @bug magic numbers */
        /** @bug might overflow buffer */
        b = _putd(to, (val < 120) ? (val / 40) : 2);
        /** @bug might overflow buffer */
        *b++ = '.';
        /** @bug magic numbers */
        /** @bug might overflow buffer */
        b = _putd(b, (val < 120) ? (val % 40) : val - 80);
        /** @bug callers seem to assume that mode is a boolean */
        if (!(mode & ASN_READ))
        {
            lth = b - to;
            b = to;
        }
        if (c < e)
            /** @bug might overflow buffer */
            *b++ = '.';
    }
    while (c < e)
    {
        /**
         * @bug
         *     This logic does not properly handle OID components that
         *     are too big to fit in an unsigned long
         */
        /** @bug invalid read if c >= e */
        for (val = 0; (*c & 0x80); c++)
        {
            val = (val << 7) + (*c & 0x7F);
        }
        val = (val << 7) + *c++;
        /** @bug might overflow buffer */
        b = _putd(b, val);
        if (c < e)
            /** @bug might overflow buffer */
            *b++ = '.';
        /** @bug callers seem to assume that mode is a boolean */
        if (!(mode & ASN_READ))
        {
            lth += b - to;
            b = to;
        }
    }
    /** @bug callers seem to assume that mode is a boolean */
    if ((mode & ASN_READ))
        /** @bug might overflow buffer */
        *b++ = 0;
    /** @bug callers seem to assume that mode is a boolean */
    return (mode & ASN_READ) ? (b - to) : ++lth;
}
