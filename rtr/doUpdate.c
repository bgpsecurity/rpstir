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
 * Copyright (C) Raytheon BBN Technologies Corp. 2007.  All Rights Reserved.
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

#include "err.h"
#include "scmf.h"
#include "querySupport.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

// number of hours to retain incremental updates
// should be at least 24 + the maximum time between updates, since need
//   to always have not just all those within the last 24 hours but also
//   one more beyond these
#define RETENTION_HOURS_DEFAULT 96

static scm      *scmp = NULL;
static scmcon   *connection = NULL;
static scmsrcha *roaSrch = NULL;
static scmtab   *roaTable = NULL;
static scmtab   *nonceTable = NULL;
static scmtab   *fullTable = NULL;
static scmtab   *updateTable = NULL;
static scmsrcha *snSrch = NULL;
static scmsrcha *incrSrch = NULL;
static scmtab   *incrTable = NULL;

// serial number of this and previous update
static uint prevSerialNum, currSerialNum, lastSerialNum;

static void setupSnQuery(scm *scmp) {
	snSrch = newsrchscm(NULL, 1, 0, 1);
	addcolsrchscm(snSrch, "serial_num", SQL_C_ULONG, 8);
	snSrch->wherestr = NULL;
	updateTable = findtablescm(scmp, "rtr_update");
	if (updateTable == NULL) printf("Cannot find table rtr_update\n");
}

/* helper function for getLastSerialNumber */
static int setLastSN(scmcon *conp, scmsrcha *s, int numLine) {
	lastSerialNum = *((uint *) (s->vec[0].valptr));
	return -1;    // stop after first row
}

/****
 * find the serial number from the most recent update
 ****/
static uint getLastSerialNumber(scmcon *connect, scm *scmp) {
	lastSerialNum = 0;
	if (snSrch == NULL) setupSnQuery(scmp);
	searchscm (connect, updateTable, snSrch, NULL, setLastSN,
			   SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_BREAK_VERR,
			   "create_time desc");
	return lastSerialNum;
}

/*****
 * allows overriding of retention time for data via environment variable
 *****/
static int retentionHours() {
	if (getenv("RTR_RETENTION_HOURS") != NULL)
		return atoi(getenv("RTR_RETENTION_HOURS"));
	return RETENTION_HOURS_DEFAULT;
}


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

	if (! checkValidity((char *)s->vec[2].valptr, 0, scmp, connection)) return -1;
	while ((end = strchr(ptr, '\n')) != 0) {
		*end = '\0';
		snprintf(msg, sizeof(msg),
				 "insert into %s values (%d, \"%s\", %d, \"%s\");",
				 fullTable->tabname, currSerialNum, filename, asn, ptr);
		statementscm_no_data(connection, msg);
		ptr = end + 1;
	}
	return 1;
}

/******
 * callback that writes withdrawals into the incremental table
 *****/
static int writeWithdrawal(scmcon *conp, scmsrcha *s, int numLine) {
	char msg[1024];
	conp = conp; numLine = numLine;
	uint asn = *((uint *)s->vec[0].valptr);
	char *ipAddr = (char *)s->vec[1].valptr;
	snprintf(msg, sizeof(msg),
			 "insert into %s values (%d, false, %d, \"%s\");",
			 incrTable->tabname, currSerialNum, asn, ipAddr);
	statementscm_no_data(connection, msg);
	return 1;
}

/******
 * callback that writes announcements into the incremental table
 *****/
static int writeAnnouncement(scmcon *conp, scmsrcha *s, int numLine) {
	char msg[1024];
	conp = conp; numLine = numLine;
	uint asn = *((uint *)s->vec[0].valptr);
	char *ipAddr = (char *)s->vec[1].valptr;
	snprintf(msg, sizeof(msg),
			 "insert into %s values (%d, true, %d, \"%s\");",
			 incrTable->tabname, currSerialNum, asn, ipAddr);
	statementscm_no_data(connection, msg);
	return 1;
}


int main(int argc, char **argv) {
	char msg[1024];
	int sta;
	uint nonce_count;

	// initialize the database connection
	scmp = initscm();
	checkErr(scmp == NULL, "Cannot initialize database schema\n");
	connection = connectscm (scmp->dsn, msg, sizeof(msg));
	checkErr(connection == NULL, "Cannot connect to database: %s\n", msg);

	nonceTable = findtablescm(scmp, "rtr_nonce");
	checkErr(nonceTable == NULL, "Cannot find table rtr_nonce\n");

	sta = newhstmt(connection);
	checkErr(!SQLOK(sta), "Can't create a new statement handle\n");
	sta = statementscm(connection, "SELECT COUNT(*) FROM rtr_nonce;");
	checkErr(sta < 0, "Can't query rtr_nonce\n");
	sta = getuintscm(connection, &nonce_count);
	pophstmt(connection);
	checkErr(sta < 0, "Can't get results of querying rtr_nonce\n");
	if (nonce_count != 1) {
		statementscm_no_data(connection, "TRUNCATE TABLE rtr_nonce;");
		statementscm_no_data(connection, "TRUNCATE TABLE rtr_update;");
		statementscm_no_data(connection, "TRUNCATE TABLE rtr_full;");
		statementscm_no_data(connection, "TRUNCATE TABLE rtr_incremental;");
		statementscm_no_data(connection, "INSERT INTO rtr_nonce (cache_nonce) VALUES (FLOOR(RAND() * (1 << 16)));");
	}

	// find the last serial number
	prevSerialNum = getLastSerialNumber(connection, scmp);
	currSerialNum = (prevSerialNum == UINT_MAX) ? 1 : (prevSerialNum + 1);

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

	// write all the data into the database (done writing "full")
	searchscm (connection, roaTable, roaSrch, NULL,
			   writeROAData, SCM_SRCH_DOVALUE_ALWAYS, NULL);

        // setup to compute incremental

	if (incrSrch == NULL) {
		incrSrch = newsrchscm(NULL, 2, 0, 1);
		addcolsrchscm(incrSrch, "t1.asn", SQL_C_ULONG, 8);
		addcolsrchscm(incrSrch, "t1.ip_addr", SQL_C_CHAR, 50);
		incrTable = findtablescm(scmp, "rtr_incremental");
	}

	// first, find withdrawal
	snprintf (incrSrch->wherestr, WHERESTR_SIZE,
			  "t1.serial_num = t2.serial_num - 1 and t1.roa_filename = t2.roa_filename and t1.ip_addr = t2.ip_addr\nt2.serial_num is null and t1.serial_num = %d", prevSerialNum);
	searchscm (connection, fullTable, incrSrch, NULL, writeWithdrawal,
			   SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN_SELF, NULL);

	// then, find announcements
	snprintf (incrSrch->wherestr, WHERESTR_SIZE,
			  "t1.serial_num = t2.serial_num + 1 and t1.roa_filename = t2.roa_filename and t1.ip_addr = t2.ip_addr\nt2.serial_num is null and t1.serial_num = %d", currSerialNum);
	searchscm (connection, fullTable, incrSrch, NULL, writeAnnouncement,
			   SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN_SELF, NULL);

	// write the current serial number and time, making the data available
	snprintf(msg, sizeof(msg), "insert into rtr_update values (%d, now());",
			 currSerialNum);
	statementscm_no_data(connection, msg);

    // clean up all the data no longer needed
	// save last two full updates so that no problems at transition
	//   (with client still receiving data from previous one)
	char *str = "%s where create_time < adddate(now(), interval -%d hour);";
	snprintf(msg, sizeof(msg),
			 "delete from rtr_full where serial_num<>%d and serial_num<>%d;",
			 prevSerialNum, currSerialNum);
	statementscm_no_data(connection, msg);
	snprintf(msg, sizeof(msg), str,
			 "delete rtr_incremental from rtr_incremental inner join rtr_update on rtr_incremental.serial_num = rtr_update.serial_num",
			 retentionHours());
	statementscm_no_data(connection, msg);
	snprintf(msg, sizeof(msg), str, "delete from rtr_update",
			 retentionHours());
	statementscm_no_data(connection, msg);

	return 0;
}
