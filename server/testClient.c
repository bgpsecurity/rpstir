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
 * Sample client for the purposes of testing and demonstrating
 *   use of the library
 * This is just for unit testing, and should not be used as the
 *   basis for a real client in general.
 * Look at sampleClient instead for a model for a real client.
 ***********************/

#include "pdu.h"
#include "sshComms.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define checkerr(s, args...) if ((s) < 0) { fprintf(stderr, args); exit(-1); }

#define checkerr2(s, args...) if (s) { fprintf(stderr, args); return -1; }

static int getBits(uint val, uint start, uint len) {
	return (val << start) >> (32 - len);
}

static int doResponses(PDU *request, int expectedNum) {
	PDU *response;
	int i, numRecords = 0;
	IPPrefixData *prefixData;
	char msg[256];

	checkerr(writePDU(request), "Error writing request\n");
	checkerr2(! (response = readPDU(msg)), "Error reading cache response\n");
	checkerr2(response->pduType != PDU_CACHE_RESPONSE,
			  "Was expecting cache response, got %d\n", response->pduType);
	freePDU(response);
	for (response = readPDU(msg);
		 response && (response->pduType != PDU_END_OF_DATA);
		 response = readPDU(msg)) {
		numRecords++;
		prefixData = (IPPrefixData *) response->typeSpecificData;
		if (response->pduType == PDU_IPV4_PREFIX) {
			printf("Received pdu of type IPv4 prefix\naddr = ");
			for (i = 0; i < 4; i++)
				printf("%d%s", getBits(prefixData->ipAddress[0], 8*i, 8),
					   (i == 3) ? "\n" : ".");
		} else if (response->pduType == PDU_IPV6_PREFIX) {
			printf("Received pdu of type IPv6 prefix\naddr = ");
			for (i = 0; i < 8; i++)
				printf("%x%s",
					   getBits(prefixData->ipAddress[i/2], (i%2)*16, 16),
					   (i == 7) ? "\n" : ":");
		} else {
			printf("Received unexpected pdu type %d\n", response->pduType);
			return -1;
		}
		printf ("%s as# = %d len = %d max = %d\n",
				(prefixData->flags == FLAG_ANNOUNCE) ? "ANNOUNCE" : "WITHDRAW",
				prefixData->asNumber, prefixData->prefixLength,
				prefixData->maxLength);
		freePDU(response);
	}
	checkerr2(! response, "Missing end-of-data pdu\n");
	i = *((uint *)response->typeSpecificData);
	freePDU(response);
	checkerr2(numRecords != expectedNum,
			  "Received %d records, was expecting %d records\n",
			  numRecords, expectedNum);
	return i;
}

static int expectError(PDU *request, short code) {
	PDU *response;
	char msg[256];
	checkerr(writePDU(request), "Error writing request\n");
	checkerr2(! (response = readPDU(msg)),
			  "Error reading response: %s\n", msg);
	checkerr2(response->pduType != PDU_ERROR_REPORT,
			  "Was expecting error report, got %d\n", response->pduType);
	checkerr2(response->color != code,
			  "Was expecting error code %d, got %d\n", code, response->color);
	printf("Error text (expected) = %s",
		   ((ErrorData *)response->typeSpecificData)->errorText);
	freePDU(response);
	return 0;
}

static void initStandalone(char *user, char *passwd) {
	// get password
	printf("Enter password for user %s: ", user);
    struct termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    struct termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    fgets(passwd, 128, stdin);
	passwd[strlen(passwd)-1] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	printf("\n");

	// init cryptlib stuff
	checkerr(initSSH(), "Error initializing SSH\n");
}

static void doOpen(CRYPT_SESSION *sessionp, char *host, int port,
				   char *user, char *passwd) {
	checkerr(sshOpenClientSession(sessionp, host, port, user, passwd),
			 "Error opening client session\n");
	setSession(*sessionp);
}

static int waitNotify(int standalone) {
	PDU *response;
	char msg[256];
	printf("\n\nWaiting for notify\n");
	if (standalone) {
		while (! (response = readPDU(msg))) {
			sleep(1);
		}
	} else {
		checkerr2(! (response = readPDU(msg)),
				  "Error reading notification: %s\n", msg);
	}
	checkerr2(response->pduType != PDU_SERIAL_NOTIFY,
			  "Was expecting serial notify, got %d\n", response->pduType);
	freePDU(response);
	return 0;
}

#define NEXT_WITH_WAIT								  \
	if (doNotify) {									  \
		checkerr(waitNotify(standalone),			  \
				 "Failed to receive notification\n"); \
	} else {										  \
		sshCloseSession(session);					  \
		sleep(10);									  \
		doOpen(&session, host, port, user, passwd);	  \
	}

#define NEXT_WITHOUT_WAIT							\
	if (! doNotify) {								\
		sshCloseSession(session);					\
		doOpen(&session, host, port, user, passwd); \
	}

int main(int argc, char **argv) {
	CRYPT_SESSION session;
	PDU request, *response;
	char msg[256], *host = "localhost";
	int i, standalone = 0, port = DEFAULT_SSH_PORT;
	int diffPort = 0;    // indicates whether standalone server
	int serialNum, doNotify = 1;
	char *user, passwd[128];

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-s") == 0) {
			standalone = 1;
		} else if (strcmp(argv[i], "-p") == 0) {
			port = atoi(argv[++i]);
			diffPort = port != DEFAULT_SSH_PORT;
		} else if (strcmp(argv[i], "-h") == 0) {
			host = argv[++i];
		} else {
			printf("Usage: testClient [-s] [-h host] [-p port]\n");
			return -1;
		}
	}
	user = strdup(getenv("USER"));

	if (standalone) {
		initStandalone(user, passwd);
		doOpen(&session, host, port, user, passwd);
		doNotify = ! diffPort;
	} else {
		checkerr(initSSHProcess(host, DEFAULT_SSH_PORT, user),
				 "Problem forking child ssh process");
	}

	printf("Testing errors at startup, first too early reset query\n");
	fillInPDUHeader(&request, PDU_RESET_QUERY, 1);
	checkerr(expectError(&request, ERR_NO_DATA),
			 "failed on early reset query\n");

	NEXT_WITHOUT_WAIT

	printf("\nThen too early serial query\n");
	fillInPDUHeader(&request, PDU_SERIAL_QUERY, 1);
	checkerr(expectError(&request, ERR_NO_DATA),
			 "failed on early serial query\n");

	NEXT_WITH_WAIT

	printf("\n\nDoing initial reset query\n");
	fillInPDUHeader(&request, PDU_RESET_QUERY, 1);
	checkerr(serialNum = doResponses(&request, 10), "Failed on reset query\n");

	NEXT_WITH_WAIT

	printf("\n\nDoing serial query\n");
	fillInPDUHeader(&request, PDU_SERIAL_QUERY, 1);
	*((uint *) request.typeSpecificData) = serialNum;
	checkerr(serialNum = doResponses(&request, 12),
			 "Failed on serial query\n");

	NEXT_WITH_WAIT

	printf("\n\nRepeat serial query\n");
	checkerr(doResponses(&request, 18), "Failed on serial query\n");

	NEXT_WITHOUT_WAIT

	printf("\n\nAgain, but now just most recent data\n");
	*((uint *) request.typeSpecificData) = serialNum;
	checkerr(doResponses(&request, 6), "Failed on serial query\n");

	NEXT_WITHOUT_WAIT

	printf("\n\nDoing serial query with reset response\n");
	*((uint *) request.typeSpecificData) = 8723;
	checkerr(writePDU(&request), "Error writing serial query\n");
	checkerr2(! (response = readPDU(msg)),
			  "Error reading cache reset: %s\n", msg);
	checkerr2(response->pduType != PDU_CACHE_RESET,
			  "Was expecting cache reset, got %d\n", response->pduType);
	freePDU(response);

	NEXT_WITHOUT_WAIT

	printf("\n\nDoing final reset query\n");
	fillInPDUHeader(&request, PDU_RESET_QUERY, 1);
	checkerr(doResponses(&request, 16), "Failed on reset query\n");

	NEXT_WITHOUT_WAIT

	printf("\nDoing illegal request\n");
	fillInPDUHeader(&request, PDU_END_OF_DATA, 1);
	expectError(&request, ERR_INVALID_REQUEST);

	printf("\nCompleted single server tests successfully\n");

	if (! standalone) {
		printf("\nType return when checked for child process: ");
		getchar();
		killSSHProcess();
		printf("\nType return when checked that no child process: ");
		getchar();
	}

	return 1;
}
