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

/************************
 * Get the next round of RTR data into the database
 ***********************/

#include "scmf.h"
#include "err.h"
#include "querySupport.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

static scm      *scmp = NULL;
static scmcon   *connect = NULL;
static scmsrcha *lastSNSrch = NULL;
static scmsrcha *roaSrch = NULL;
static scmtab   *roaTable = NULL;
static scmtab   *updateTable = NULL;
static scmtab   *fullTable = NULL;

static unsigned int lastSerialNumber;  // way to pass back result

/* helper function for getLastSerialNumber */
static int setLastSN(scmcon *conp, scmsrcha *s, int numLine) {
	lastSerialNumber = *((unsigned int *) (s->vec[0].valptr));
	return -1;    // stop after first row
}

/****
 * find the serial number from the most recent update
 ****/
static int getLastSerialNumber() {
	lastSerialNumber = 0;
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
	return lastSerialNumber;
}

int main(int argc, char **argv) {
	unsigned int serialNum;
	char msg[1024];

	// initialize the database connection
	scmp = initscm();
	checkErr(scmp == NULL, "Cannot initialize database schema\n");
	connect = connectscm (scmp->dsn, msg, sizeof(msg));
	checkErr(connect == NULL, "Cannot connect to database: %s\n", msg);

	// find the last serial number
	serialNum = getLastSerialNumber();
	serialNum = (serialNum == UINT_MAX) ? 1 : (serialNum + 1);

	// write all the data into the database

	// write the current serial number and time, making the data available
	snprintf(msg, sizeof(msg), "insert into %s values (%d, now());",
			 updateTable->tabname, serialNum);
	statementscm(connect, msg);

	return 0;
}
