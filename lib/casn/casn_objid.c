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
#include "util/stringutils.h"

#include <limits.h>

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
    /** @bug error code ignored without explanation */
    c = calloc(1, lth);
    /** @bug error code ignored without explanation */
    read_objid(casnp, c);
    if (lth < lth2)
        ansr = lth;
    else
        ansr = lth2;
    /**
     * @bug
     *     Callers might expect -1 to indicate that the first OID
     *     "comes before" the second OID in the OID tree, but a
     *     comparison of OID strings with strcmp() or memcmp() doesn't
     *     provide this property.  If -1 is returned, the first OID
     *     may or may not come before the second OID in the OID tree.
     *     Similarly, if 1 is returned, the first OID may or may not
     *     come after the second OID.  Thus, -1 and 1 must be treated
     *     the same by the caller, so this function might as well
     *     return 0 if the two are the same, positive if they are
     *     different, and negative on error.
     */
    /** @bug should just use strcmp() instead */
    if ((ansr = memcmp(c, objid, ansr)) == 0)
    {
        /**
         * @bug
         *     this will never be true because the null terminator is
         *     included in the comparison, so if the memcmp() returns
         *     0 then the lengths must equal each other
         */
        if (lth2 > lth)
            ansr = 1;
        /**
         * @bug
         *     this will never be true because the null terminator is
         *     included in the comparison, so if the memcmp() returns
         *     0 then the lengths must equal each other
         */
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
    /** @bug should use real buffer length to avoid overflow */
    return _readsize_objid(casnp, to, INT_MAX, 1);
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
    return _readsize_objid(casnp, buf, sizeof(buf), 0);
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
    size_t tolen,
    int mode)
{
    int lth = 0;
    uchar *c = casnp->startp;
    uchar *e = &c[casnp->lth];
    char *b = to;
    ulong val;

    if (casnp->tag == ASN_NOTYPE && (lth = _check_enum(&casnp)) <= 0)
        /** @bug null terminator hasn't been written if lth is 0 */
        return lth;
    if (!casnp->lth)
        /** @bug null terminator hasn't been written */
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
         *     BER and DER require the minimal number of octets.  This
         *     logic ignores excess octets.  Should it error out
         *     instead?
         */
        for (val = 0; c < e && (*c & 0x80); c++)
        {
            val = (val << 7) + (*c & 0x7F);
        }
        /** @bug invalid read if c == e */
        val = (val << 7) + *c++;
        /** @bug magic numbers */
        /** @bug _putd() takes a long, not an unsigned long */
        b = _putd(b, tolen - (b - to), (val < 120) ? (val / 40) : 2);
        b += xstrlcpy(b, ".", tolen - (b - to));
        /** @bug magic numbers */
        /** @bug _putd() takes a long, not an unsigned long */
        b = _putd(b, tolen - (b - to), (val < 120) ? (val % 40) : val - 80);
        /** @bug callers seem to assume that mode is a boolean */
        if (!(mode & ASN_READ))
        {
            lth = b - to;
            b = to;
        }
        if (c < e)
        {
            b += xstrlcpy(b, ".", tolen - (b - to));
        }
    }
    while (c < e)
    {
        /**
         * @bug
         *     This logic does not properly handle OID components that
         *     are too big to fit in an unsigned long
         */
        /**
         * @bug
         *     BER and DER require the minimal number of octets.  This
         *     logic ignores excess octets.  Should it error out
         *     instead?
         */
        /** @bug invalid read if c >= e */
        for (val = 0; (*c & 0x80); c++)
        {
            val = (val << 7) + (*c & 0x7F);
        }
        /** @bug invalid read if c >= e */
        val = (val << 7) + *c++;
        /** @bug _putd() takes a long, not an unsigned long */
        b = _putd(b, tolen - (b - to), val);
        if (c < e)
        {
            b += xstrlcpy(b, ".", tolen - (b - to));
        }
        /** @bug callers seem to assume that mode is a boolean */
        if (!(mode & ASN_READ))
        {
            lth += b - to;
            b = to;
        }
    }
    // add one to include the nul terminator in the length
    /** @bug callers seem to assume that mode is a boolean */
    return (mode & ASN_READ) ? (b - to) + 1 : ++lth;
}
