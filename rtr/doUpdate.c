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
	(void)conp;
	(void)numLine;
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
	char msg[1024];
	conp = conp; numLine = numLine;

	if (! checkValidity((char *)s->vec[2].valptr, 0, scmp, connection)) return -1;
	while ((end = strstr(ptr, ", ")) != NULL) {
		end[0] = '\0';
		end[1] = '\0';
		snprintf(msg, sizeof(msg),
				 "insert ignore into %s values (%u, %u, \"%s\");",
				 fullTable->tabname, currSerialNum, asn, ptr);
		statementscm_no_data(connection, msg);
		ptr = end + 2;
	}
	if (ptr[0] != '\0') {
		snprintf(msg, sizeof(msg),
				 "insert ignore into %s values (%u, %u, \"%s\");",
				 fullTable->tabname, currSerialNum, asn, ptr);
		statementscm_no_data(connection, msg);
	}
	return 1;
}


int main(int argc, char **argv) {
	char msg[1024];
	int sta;
	uint nonce_count;
	int first_time = 0;

	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s <staleness spec file>\n", argv[0]);
		return EXIT_FAILURE;
	}

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
		first_time = 1;
	}

	// find the last serial number
	prevSerialNum = getLastSerialNumber(connection, scmp);
	currSerialNum = (prevSerialNum == UINT_MAX) ? 0 : (prevSerialNum + 1);

	// setup up the query if this is the first time
	// note that the where string is set to only select valid roa's, where
    //   the definition of valid is given by the staleness specs
	if (roaSrch == NULL) {
		QueryField *field;
		roaSrch = newsrchscm(NULL, 3, 0, 1);
		field = findField("asn");
		addcolsrchscm(roaSrch, "asn", field->sqlType, field->maxSize);
		field = findField("ip_addrs");
		addcolsrchscm(roaSrch, "ip_addrs", field->sqlType, field->maxSize);
		field = findField("ski");
		addcolsrchscm(roaSrch, "ski", field->sqlType, field->maxSize);
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

	if (!first_time)
	{
		char differences_query_fmt[] =
			"INSERT INTO rtr_incremental (serial_num, is_announce, asn, ip_addr)\n"
			"SELECT %u, %d, t1.asn, t1.ip_addr\n"
			"FROM rtr_full AS t1\n"
			"LEFT JOIN rtr_full AS t2 ON t2.serial_num = %u AND t2.asn = t1.asn AND t2.ip_addr = t1.ip_addr\n"
			"WHERE t1.serial_num = %u AND t2.serial_num IS NULL;";

		// announcements
		snprintf(msg, sizeof(msg), differences_query_fmt,
			prevSerialNum, 1,
			prevSerialNum, currSerialNum);
		statementscm_no_data(connection, msg);

		// withdrawals
		snprintf(msg, sizeof(msg), differences_query_fmt,
			prevSerialNum, 0,
			currSerialNum, prevSerialNum);
		statementscm_no_data(connection, msg);
	}

	// write the current serial number and time, making the data available
	snprintf(msg, sizeof(msg), "insert into rtr_update values (%u, now());",
			 currSerialNum);
	statementscm_no_data(connection, msg);

    // clean up all the data no longer needed
	// save last two full updates so that no problems at transition
	//   (with client still receiving data from previous one)
	snprintf(msg, sizeof(msg),
			 "delete from rtr_full where serial_num<>%u and serial_num<>%u;",
			 prevSerialNum, currSerialNum);
	statementscm_no_data(connection, msg);

	snprintf(msg, sizeof(msg),
		"delete from rtr_update\n"
		"where create_time < adddate(now(), interval -%d hour)\n"
		"and serial_num<>%u and serial_num<>%u;",
		retentionHours(),
		prevSerialNum, currSerialNum);
	statementscm_no_data(connection, msg);

	statementscm_no_data(connection,
		 "delete rtr_incremental\n"
		 "from rtr_incremental\n"
		 "left join rtr_update on rtr_incremental.serial_num = rtr_update.serial_num\n"
		 "where rtr_update.serial_num is null;");

	return 0;
}
