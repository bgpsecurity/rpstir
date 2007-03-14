/* Jan 25 1996 324U  */
/* Jan 25 1996 GARDINER added constraint errors */
/* Aug 22 1995 261U  */
/* Aug 22 1995 GARDINER added ASN_FILE_ERR */
/* Jun 30 1995 236U  */
/* Jun 30 1995 GARDINER added ASN_LENGTH_ERR */
/* Jun 12 1995 221U  */
/* Jun 12 1995 GARDINER added multi-defines */
/* May 22 1995 212U  */
/* May 22 1995 GARDINER fixed ifdef */
/* May 22 1995 209U  */
/* May 22 1995 GARDINER re-arranged error numbers */
/* Apr  6 1995 162U  */
/* Apr  6 1995 GARDINER header */
/* Feb 21 1995 156U  */
/* Feb 21 1995 GARDINER added ASN_MATCH_ERR */
/* Nov 17 1994 113U  */
/* Nov 17 1994 GARDINER added ASN_MASK_ERR and ASN_NO_CHOICE_ERR */
/* Oct 12 1994  83U  */
/* Oct 12 1994 GARDINER added ASN_UNDEF_VALUE */
/* Aug  8 1994  45U  */
/* Aug  8 1994 GARDINER fixed */
/* Aug  2 1994  42U  */
/* Aug  2 1994 GARDINER add error message ASN_NONE_ERR */
/* Jul 27 1994  38U  */
/* Jul 27 1994 GARDINER started */
/*****************************************************************************
File:     asn_error.h
Contents: Error codes for ASN.1-object library.
System:   ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

COPYRIGHT 1995 BBN Systems and Technologies, A Division of BBN Inc.
150 CambridgePark Drive
Cambridge, Ma. 02140
617-873-4000
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
