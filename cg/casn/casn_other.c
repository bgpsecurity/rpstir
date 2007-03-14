/* Sep  1 2004 803U  */
/* Sep  1 2004 GARDINER started */
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
*****************************************************************************/

char casn_other_sfcsid[] = "@(#)casn_other.c 803P";
#include "casn.h"

int encodesize_casn(struct casn *casnp, uchar **pp)
    {
    int lth;

    *pp = (uchar *)0;
    if ((lth = size_casn(casnp)) < 0) return lth;
    *pp = calloc(1, lth);
    return encode_casn(casnp, *pp);
    }

int readvsize_casn(struct casn *casnp, uchar **pp)
    {
    int lth;

    *pp = (uchar *)0;
    if ((lth = vsize_casn(casnp)) < 0) return lth;
    *pp = calloc(1, lth);
    return read_casn(casnp, *pp);
    }

int readvsize_objid(struct casn *casnp, char **pp)
    {
    int lth;

    *pp = (uchar *)0;
    if ((lth = vsize_objid(casnp)) < 0) return lth;
    *pp = calloc(1, lth);
    return read_objid(casnp, *pp);
    }

