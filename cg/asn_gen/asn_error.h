/* $Id$ */
/*****************************************************************************
File:     asn_error.h
Contents: Error codes for ASN.1-object library.
System:   ASN development.
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
 * Copyright (C) BBN Technologies 1995-2010.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK *****
*****************************************************************************/
#ifndef _ASN_ERROR_H
#define _ASN_ERROR_H
/* $Header: /nfs/sub-rosa/u2/IOS_Project/ASN/Dev/rcs/lib/asn_obj/asn_error.h,v 1.2 1995/01/11 22:23:34 jlowry Exp gardiner $ */
/* sfcsid[] = "@(#)asn_error.h 324P" */

void asn_error(int, char *);

#define ASN_MATCH_ERR       1
#define ASN_MEM_ERR         2
#define ASN_GEN_ERR         3
#define ASN_CHOICE_ERR      4
#define ASN_OF_ERR          5
#define ASN_MANDATORY_ERR   6
#define ASN_NOT_OF_ERR      7
#define ASN_OF_BOUNDS_ERR   8
#define ASN_EMPTY_ERR       9
#define ASN_DEFINER_ERR     10
#define ASN_NO_DEF_ERR      11
#define ASN_BOUNDS_ERR      12
#define ASN_TYPE_ERR        13
#define ASN_TIME_ERR        14
#define ASN_CODING_ERR      15
#define ASN_NULL_PTR        16
#define ASN_NONE_ERR        17
#define ASN_UNDEF_VALUE     18
#define ASN_NO_CHOICE_ERR   19
#define ASN_MASK_ERR        20
#define ASN_DEFINED_ERR     21
#define ASN_LENGTH_ERR      22
#define ASN_FILE_ERR        23
#define ASN_CONSTRAINT_ERR  24
#define ASN_RECURSION_ERR   25
#endif /* _ASN_ERROR_H */
