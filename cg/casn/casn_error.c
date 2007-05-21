/* $Id$ */
/* Mar 25 2004 743U  */
/* Mar 25 2004 GARDINER started */
/* */
/*****************************************************************************
File:     casn_error.c
Contents: Function to report errors
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

COPYRIGHT 2004 BBN Systems and Technologies
10 Moulton St.
Cambridge, Ma. 02138
617-873-3000
*****************************************************************************/

char casn_error_sfcsid[] = "@(#)casn_error.c 743P";
#include <stdio.h>

void casn_error(int num, char *msg) 
    {
    fprintf(stderr, "Error #%d: %s\n", num, msg);
    fflush(stderr);
    }

