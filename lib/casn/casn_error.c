/*
 * $Id$ 
 */
/*****************************************************************************
File:     casn_error.c
Contents: Function to report errors
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

*****************************************************************************/

char casn_error_sfcsid[] = "@(#)casn_error.c 743P";
#include <stdio.h>

void casn_error(
    int num,
    char *msg)
{
    fprintf(stderr, "Error #%d: %s\n", num, msg);
    fflush(stderr);
}
