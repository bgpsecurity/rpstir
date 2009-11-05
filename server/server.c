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
#include "err.h"
#include "rtrUtils.h"
#include "querySupport.h"
#include "sshComms.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static scm      *scmp = NULL;
static scmcon   *connect = NULL;
static scmsrcha *fullSrch = NULL;
static scmtab   *fullTable = NULL;
static scmsrcha *incrSrch = NULL;
static scmtab   *incrTable = NULL;

static PDU response;
static IPPrefixData prefixData;
static FILE *logfile;


/* send an error report PDU to the client */
static void sendErrorReport(PDU *request, int type, char *msg) {
	ErrorData errorData;
	fillInPDUHeader(&response, PDU_ERROR_REPORT, 0);
	response.color = type;
	response.typeSpecificData = &errorData;
	errorData.badPDU = request;
	errorData.errorText = msg;
	if (writePDU(&response) == -1) {
		printf("Error writing error report, text = %s\n", msg);
	}
}

/* callback that sends a single address to the client */
static int sendResponse(scmsrcha *s, char isAnnounce) {
	char *ptr1 = (char *)s->vec[1].valptr, *ptr2;

	response.typeSpecificData = &prefixData;
	prefixData.flags = isAnnounce ? FLAG_ANNOUNCE : FLAG_WITHDRAW;
	prefixData.dataSource = SOURCE_RPKI;
	prefixData.asNumber = *((uint *)s->vec[0].valptr);

	ptr2 = strchr(ptr1, '/');
	*ptr2 = '\0';
	// IPv4
	if (strchr(ptr1, '.')) {
	  fillInPDUHeader(&response, PDU_IPV4_PREFIX, 0);
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
		  val = (val << 16) + strtol(ptr1, NULL, 16);
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
	if (writePDU(&response) == -1) {
	  printf("Error writing response\n");
	  return -1;
	}

	return 0;
}

static int sendFullResponse(scmcon *conp, scmsrcha *s, int numLine) {
	conp = conp; numLine = numLine;
	return sendResponse(s, 1);
}

static int sendIncrResponse(scmcon *conp, scmsrcha *s, int numLine) {
	conp = conp; numLine = numLine;
	return sendResponse(s, *((char *)s->vec[2].valptr));
}

static void handleSerialQuery(PDU *request) {
	uint oldSN = *((uint *)request->typeSpecificData);
	uint *newSNs = getMoreRecentSerialNums(connect, scmp, oldSN);
	int i;

	// handle case when error because the original serial number is not
	//    in the database, so there is no way to get incremental updates
	// in this case, send cache reset response
	if (! newSNs) {
		fillInPDUHeader(&response, PDU_CACHE_RESET, 1);
		if (writePDU(&response) == -1) {
			printf("Error writing cache reset response\n");
		}
		return;
	}

	fillInPDUHeader(&response, PDU_CACHE_RESPONSE, 1);
	if (writePDU(&response) == -1) {
		printf("Error writing cache response\n");
		return;
	}

	// setup up the query if this is the first time
	if (incrSrch == NULL) {
		incrSrch = newsrchscm(NULL, 3, 0, 1);
		addcolsrchscm(incrSrch, "asn", SQL_C_ULONG, 8);
		addcolsrchscm(incrSrch, "ip_addr", SQL_C_CHAR, 50);
		addcolsrchscm(incrSrch, "is_announce", SQL_C_BIT, 1);
		incrTable = findtablescm(scmp, "rtr_incremental");
	}

	// separate query for each serial number in list of recent ones
	// in callback, first write all withdrawals and then all announcements
	//     for the current serial number
	for (i = 0; newSNs[i] != 0; i++) {
		snprintf (incrSrch->wherestr, WHERESTR_SIZE,
				  "serial_num = %d", newSNs[i]);
		searchscm (connect, incrTable, incrSrch, NULL,
				   sendIncrResponse, SCM_SRCH_DOVALUE_ALWAYS, "is_announce");
	}

	// finish up by sending the end of data PDU
	fillInPDUHeader(&response, PDU_END_OF_DATA, 0);
	response.typeSpecificData = &newSNs[i-1];
	if (writePDU(&response) == -1) {
		printf("Error writing end of data\n");
		return;
	}
}

static void handleResetQuery(PDU *request) {
	uint serialNum;
	char msg[256];

	serialNum = getLastSerialNumber(connect, scmp);

	// handle error condition when no data yet in database
	if (serialNum == 0) {
		snprintf(msg, sizeof(msg),
				 "First database update has not yet been performed\n");
		sendErrorReport(request, ERR_NO_DATA, msg);
		return;
	}

	fillInPDUHeader(&response, PDU_CACHE_RESPONSE, 1);
	if (writePDU(&response) == -1) {
		printf("Error writing cache response\n");
		return;
	}

	// setup up the query if this is the first time
	if (fullSrch == NULL) {
		fullSrch = newsrchscm(NULL, 2, 0, 1);
		addcolsrchscm(fullSrch, "asn", SQL_C_ULONG, 8);
		addcolsrchscm(fullSrch, "ip_addr", SQL_C_CHAR, 50);
		snprintf (fullSrch->wherestr, WHERESTR_SIZE,
				  "serial_num = %d", serialNum);
		fullTable = findtablescm(scmp, "rtr_full");
	}

	// do the query, with callback sending out the responses
	searchscm (connect, fullTable, fullSrch, NULL,
			   sendFullResponse, SCM_SRCH_DOVALUE_ALWAYS, NULL);

	// finish up by sending the end of data PDU
	fillInPDUHeader(&response, PDU_END_OF_DATA, 0);
	response.typeSpecificData = &serialNum;
	if (writePDU(&response) == -1) {
		printf("Error writing end of data\n");
		return;
	}
}


#define checkSSH(s, args...) \
	if ((s) < 0) { fprintf(logfile, args); return -1; }

int main(int argc, char **argv) {
	CRYPT_SESSION session;
	PDU *request;
	char msg[256];
	int i, standalone = 0, port = DEFAULT_STANDALONE_PORT;
	char *logFilename = "log.rtr.server";

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-s") == 0) {
			standalone = 1;
		} else if (strcmp(argv[i], "-l") == 0) {
			logFilename = argv[++i];
		} else if (strcmp(argv[i], "-p") == 0) {
			port = atoi(argv[++i]);
		} else {
			printf("Usage: server [-s] [-l logfile] [-p port]\n");
			return -1;
		}
	}

	// open the log file
	// ??????? add time to name so that unique ???????
	logfile = fopen(logFilename, "w");
	if (logfile == NULL) {
		fprintf(stderr, "Could not open log file\n");
		return -1;
	}

	// initialize the database connection and SSH library
	scmp = initscm();
	checkErr(scmp == NULL, "Cannot initialize database schema\n");
	connect = connectscm (scmp->dsn, msg, sizeof(msg));
	checkErr(connect == NULL, "Cannot connect to database: %s\n", msg);
	if (standalone) checkSSH(initSSH(), "Error initializing SSH\n");

	while (1) {
		if (standalone) {
			checkSSH(sshOpenServerSession(&session, port),
					 "Error opening server session\n");
			setSession(session);
		}
		request = readPDU(msg);
		if (! request) {
			sendErrorReport(request, ERR_INVALID_REQUEST, msg);
			if (standalone) sshCloseSession(session);
			continue;
		}
		switch (request->pduType) {
		case PDU_SERIAL_QUERY:
			handleSerialQuery(request);
			break;
		case PDU_RESET_QUERY:
			handleResetQuery(request);
			break;
		default:
			snprintf(msg, sizeof(msg),
					 "Cannot handle request of type %d\n", request->pduType);
			sendErrorReport(request, ERR_INVALID_REQUEST, msg);
		}
		freePDU(request);
		if (standalone) sshCloseSession(session);
	}
	return 1;
}
