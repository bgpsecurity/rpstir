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
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  David Montana
 *
 * ***** END LICENSE BLOCK ***** */

/*
  $Id: query.c 857 2009-09-30 15:27:40Z dmontana $
*/

#include "rtrUtils.h"
#include "err.h"
#include "pdu.h"
#include <stdio.h>
#include <stdlib.h>

static uint lastSerialNum;  // way to pass back result
static scmsrcha *lastSNSrch = NULL;
static scmtab   *updateTable = NULL;

/* helper function for getLastSerialNumber */
static int setLastSN(scmcon *conp, scmsrcha *s, int numLine) {
	lastSerialNum = *((uint *) (s->vec[0].valptr));
	return -1;    // stop after first row
}

/****
 * find the serial number from the most recent update
 ****/
int getLastSerialNumber(scmcon *connect, scm *scmp) {
	lastSerialNum = 0;
	if (lastSNSrch == NULL) {
		lastSNSrch = newsrchscm(NULL, 1, 0, 1);
		addcolsrchscm(lastSNSrch, "serial_num", SQL_C_ULONG, 8);
		lastSNSrch->wherestr = NULL;
		updateTable = findtablescm(scmp, "rtr_update");
		checkErr(updateTable == NULL, "Cannot find table rtr_update\n");
	}
	searchscm (connect, updateTable, lastSNSrch, NULL, setLastSN,
			   SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_BREAK_VERR,
			   "create_time desc");
	return lastSerialNum;
}
