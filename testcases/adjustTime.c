/* $Id: adjustTime.c 453 2008-05-28 15:30:40Z cgardiner $ */

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2008.  All Rights Reserved.
 *
 * Contributor(s):  Charles W. Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "casn.h"

static char *units = "YMWDhms";

#define GENSIZE 15
#define UTCSIZE 13

int adjustTime(struct casn *timep, long basetime, char *deltap)
{
    // if they passed in a NULL for deltap, just use basetime
    if (deltap != NULL) {
	char *unitp = &deltap[strlen(deltap) - 1];
	if (*unitp == 'Z') {
	    // absolute time
	    if (strlen(deltap) == GENSIZE) /* generalized time? */
		/* this fn doesn't handle generalizedtime, strip century */
		deltap += (GENSIZE - UTCSIZE);
	    else if (strlen(deltap) != UTCSIZE) /* utc time? */
		return -1;	/* bad format */
	    if (time_to_ulong((ulong *)&basetime, deltap, 13) < 0)
		return -1;	/* bad format */
	} else if (strchr(units, *unitp) != 0) {
	    // relative time
	    ulong val;
	    sscanf(deltap, "%ld", &val);
	    if (*unitp == 's') ;   // val is right
	    else if (*unitp == 'm') val *= 60;
	    else if (*unitp == 'h') val *= 3600;
	    else if (*unitp == 'D') val *= (3600 * 24);
	    else if (*unitp == 'W') val *= (3600 * 24 * 7);
	    else if (*unitp == 'M') val *= (3600 * 24 * 30);
	    else if (*unitp == 'Y') val *= (3600 * 24 * 365);
	    basetime += val;
	} else {
	    // unknown delta unit, bad call
	    return -1;
	}
    }

    write_casn_time(timep, (ulong)basetime);
    return 0;
}
