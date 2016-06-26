/*****************************************************************************
File:     casn_error.c
Contents: Function to report errors
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

*****************************************************************************/

#include "casn.h"

#include <stdio.h>

static casn_error_callback default_casn_error_handler;
void
default_casn_error_handler(
    int num,
    const char *msg)
{
    fprintf(stderr, "Error #%d: %s\n", num, msg);
    fflush(stderr);
}

casn_error_callback *casn_error = &default_casn_error_handler;
