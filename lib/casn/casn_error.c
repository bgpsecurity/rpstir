/*****************************************************************************
File:     casn_error.c
Contents: Function to report errors
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

*****************************************************************************/

#include "casn_private.h"

#include <stdio.h>

void casn_error(
    int num,
    char *msg)
{
    fprintf(stderr, "Error #%d: %s\n", num, msg);
    fflush(stderr);
}
