/* $Id$ */
/*****************************************************************************
File:     casn.c
Contents: Basic functions for ASN.1 objects.
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

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

char casn_other_sfcsid[] = "@(#)casn_other.c 872P";
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
    *pp = calloc(1, lth + 1);
    return read_casn(casnp, *pp);
    }

int readvsize_objid(struct casn *casnp, char **pp)
    {
    int lth;

    *pp = (char *)0;
    if ((lth = vsize_objid(casnp)) < 0) return lth;
    *pp = calloc(1, lth);
    return read_objid(casnp, *pp);
    }

