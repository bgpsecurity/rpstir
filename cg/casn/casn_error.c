/* $Id$ */
/*****************************************************************************
File:     casn_error.c
Contents: Function to report errors
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
 * Copyright (C) BBN Technologies 2004-2010.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK *****
*****************************************************************************/

char casn_error_sfcsid[] = "@(#)casn_error.c 743P";
#include <stdio.h>

void casn_error(int num, char *msg) 
    {
    fprintf(stderr, "Error #%d: %s\n", num, msg);
    fflush(stderr);
    }

