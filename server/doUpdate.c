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

#include "rtrUtils.h"
#include "err.h"
#include "querySupport.h"
#include "pdu.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

static scm      *scmp = NULL;
static scmcon   *connect = NULL;
static scmsrcha *roaSrch = NULL;
static scmtab   *roaTable = NULL;
static scmtab   *fullTable = NULL;

static uint currSerialNum;  // serial num of current update

/******
 * callback that writes the data from a ROA into the update table
 *   if the ROA is valid
 *****/
static int writeROAData(scmcon *conp, scmsrcha *s, int numLine) {
	uint asn = *((uint *)s->vec[0].valptr);
	char *ptr = (char *)s->vec[1].valptr, *end;
	char *filename = (char *)s->vec[3].valptr;
	char msg[1024];
	conp = conp; numLine = numLine;

	if (! checkValidity((char *)s->vec[2].valptr, 0, scmp, connect)) return -1;
	while ((end = strchr(ptr, '\n')) != 0) {
		*end = '\0';
		snprintf(msg, sizeof(msg),
				 "insert into %s values (%d, \"%s\", %d, \"%s\");",
				 fullTable->tabname, currSerialNum, filename, asn, ptr);
		newhstmt(connect);
		statementscm(connect, msg);
		pophstmt(connect);
		ptr = end + 1;
	}
	return 1;
}

int main(int argc, char **argv) {
	char msg[1024];

	// initialize the database connection
	scmp = initscm();
	checkErr(scmp == NULL, "Cannot initialize database schema\n");
	connect = connectscm (scmp->dsn, msg, sizeof(msg));
	checkErr(connect == NULL, "Cannot connect to database: %s\n", msg);

	// find the last serial number
	currSerialNum = getLastSerialNumber(connect, scmp);
	currSerialNum = (currSerialNum == UINT_MAX) ? 1 : (currSerialNum + 1);

	// setup up the query if this is the first time
	// note that the where string is set to only select valid roa's, where
    //   the definition of valid is given by the staleness specs
	if (roaSrch == NULL) {
		QueryField *field;
		roaSrch = newsrchscm(NULL, 4, 0, 1);
		field = findField("asn");
		addcolsrchscm(roaSrch, "asn", field->sqlType, field->maxSize);
		field = findField("ip_addrs");
		addcolsrchscm(roaSrch, "ip_addrs", field->sqlType, field->maxSize);
		field = findField("ski");
		addcolsrchscm(roaSrch, "ski", field->sqlType, field->maxSize);
		field = findField("filename");
		addcolsrchscm(roaSrch, "filename", field->sqlType, field->maxSize);
		roaSrch->wherestr[0] = 0;
		parseStalenessSpecsFile(argv[1]);
		addQueryFlagTests(roaSrch->wherestr, 0);
		roaTable = findtablescm(scmp, "roa");
		checkErr(roaTable == NULL, "Cannot find table roa\n");
		fullTable = findtablescm(scmp, "rtr_full");
		checkErr(fullTable == NULL, "Cannot find table rtr_full\n");
	}

	// write all the data into the database
	searchscm (connect, roaTable, roaSrch, NULL,
			   writeROAData, SCM_SRCH_DOVALUE_ALWAYS, NULL);

	// write the current serial number and time, making the data available
	snprintf(msg, sizeof(msg), "insert into rtr_update values (%d, now());",
			 currSerialNum);
	statementscm(connect, msg);

	return 0;
}
