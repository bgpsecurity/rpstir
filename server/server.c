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
 * Server that implements RTR protocol
 ***********************/

#include "pdu.h"
#include "socket.h"
#include "scmf.h"
#include "err.h"
#include "querySupport.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static scm      *scmp = NULL;
static scmcon   *connect = NULL;
static scmsrcha *roaSrch = NULL;
static scmtab   *table = NULL;

static int sock;
static PDU response;
static IPPrefixData prefixData;

// for now, just for single client
static uint clientSerialNum = 0;
static uint lastSerialNum = 0;

/* callback that sends a single address to the client */
static int sendResponses(scmcon *conp, scmsrcha *s, int numLine) {
	char *ptr1 = (char *)s->vec[1].valptr, *ptr2, *end;
	conp = conp; numLine = numLine;

	response.typeSpecificData = &prefixData;
	prefixData.flags = FLAG_ANNOUNCE;
	prefixData.dataSource = SOURCE_RPKI;
	prefixData.asNumber = *((uint *)s->vec[0].valptr);

	while ((end = strchr(ptr1, '\n')) != 0) {
		fillInPDUHeader(&response, PDU_IPV4_PREFIX, 0);
		*end = '\0';
		ptr2 = strchr(ptr1, '/');
		*ptr2 = '\0';

		// IPv4
		if (strchr(ptr1, '.')) {
			uint val = 0;
			ptr1 = strtok(ptr1, ".");
			while (ptr1) {
				val = (val << 8) + atoi(ptr1);
				ptr1 = strtok(NULL, ".");
			}
			prefixData.ipAddress[0] = val;
		}
		// IPv6
		else {
			fillInPDUHeader(&response, PDU_IPV6_PREFIX, 0);
			uint i = 0, val = 0, final = 0;
			ptr1 = strtok(ptr1, ":");
			while (ptr1) {
				val = (val << 16) + atoi(ptr1);
				if (final) {
					prefixData.ipAddress[i] = val;
					val = 0;
					i++;
				}
				final = ! final;
				ptr1 = strtok(NULL, ":");
			}
		}

		ptr1 = ptr2 + 1;
		ptr2 = strchr(ptr1, '/');
		if (ptr2) *ptr2 = '\0';
		prefixData.prefixLength = atoi(ptr1);
		prefixData.maxLength = ptr2 ? atoi(ptr2+1) : prefixData.prefixLength;
		if (writePDU(&response, sock) == -1) {
			printf("Error writing response\n");
			return -1;
		}
		ptr1 = end + 1;
	}

	return 0;
}

int main(int argc, char **argv) {
	PDU *request;
	uint serialNum;
	char errMsg[1024];

	if (argc != 2) {
		printf("Usage: server stalenessSpecsFile\n");
	}

	if ((sock = getServerSocket()) == -1) {
		printf("Error opening socket\n");
		return -1;
	}
	if (! (request = readPDU(sock))) {
		printf ("Error reading reset query\n");
		return -1;
	}
	if (request->pduType != PDU_RESET_QUERY) {
		printf("Was expecting reset query, got %d\n", request->pduType);
		return -1;
	}
	fillInPDUHeader(&response, PDU_CACHE_RESPONSE, 1);
	if (writePDU(&response, sock) == -1) {
		printf("Error writing cache response\n");
		return -1;
	}

	// initialize the database connection
	scmp = initscm();
	checkErr(scmp == NULL, "Cannot initialize database schema\n");
	connect = connectscm (scmp->dsn, errMsg, 1024);
	checkErr(connect == NULL, "Cannot connect to database: %s\n", errMsg);
	connect->mystat.tabname = "roa";
	table = findtablescm(scmp, "roa");
	checkErr(table == NULL, "Cannot find table roa\n");

	// setup up the query if this is the first time
	// note that the where string is set to only select valid roa's, where
    //   the definition of valid is given by the staleness specs
	if (roaSrch == NULL) {
		roaSrch = newsrchscm(NULL, 3, 0, 1);
		addcolsrchscm(roaSrch, "asn", SQL_C_ULONG, 8);
		addcolsrchscm(roaSrch, "ip_addrs", SQL_C_CHAR, 32768);
		addcolsrchscm(roaSrch, "ski", SQL_C_CHAR, SKISIZE);
		roaSrch->wherestr[0] = 0;
		parseStalenessSpecsFile(argv[1]);
		addQueryFlagTests(roaSrch->wherestr, 0);
	}

	// do the query, with callback sending out the responses
	searchscm (connect, table, roaSrch, NULL,
			   sendResponses, SCM_SRCH_DOVALUE_ALWAYS, NULL);

	// finish up by sending the end of data PDU
	fillInPDUHeader(&response, PDU_END_OF_DATA, 0);
	response.typeSpecificData = &serialNum;
	serialNum = lastSerialNum;
	clientSerialNum = lastSerialNum;
	if (writePDU(&response, sock) == -1) {
		printf("Error writing end of data\n");
		return -1;
	}

	printf("Completed successfully\n");
	return 1;
}
