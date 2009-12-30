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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include "coreClient.h"
#include "sshComms.h"

typedef struct _ServerInfo {
	char *host;       // host name where server lives
	char *user;       // user name to use for logging in (eventually this
	char standalone;  // whether client is standalone or uses SSH client
	int port;         // SSH port to connect to at host
	                  // will be replace by public/private keys)
} ServerInfo;

#define DEFAULT_USER "rpkirtr"

#define RECOVERABLE_ERROR -1
#define NONRECOVERABLE_ERROR -2

#define MAX_SERVERS 64
static ServerInfo servers[MAX_SERVERS];
static int numServers = 0;

#define STR_SIZE 256
static void parseServers (char *filename) {
	char str[STR_SIZE];
	FILE *input = fopen (filename, "r");

	if (input == NULL) {
		fprintf (stderr, "Could not open server hosts file: %s\n", filename);
		exit(-1);
	}
	while (fgets (str, STR_SIZE, input)) {
		char *tok = strtok(str, " ,\t\n");
		if ((! tok) || (tok[0] == '#')) continue;
		if (numServers >= MAX_SERVERS) {
			fprintf(stderr, "Number of servers greater than max: %d\n",
					MAX_SERVERS);
			exit(-1);
		}
		servers[numServers].host = strdup(tok);

		tok = strtok(NULL, " ,\t\n");
		servers[numServers].user = strdup(tok ? tok : DEFAULT_USER);

		tok = strtok(NULL, " ,\t\n");
		servers[numServers].standalone =
			tok && (strlen(tok) > 0) && (tok[0] == 'y' || tok[0] == 'Y');

		tok = strtok(NULL, " ,\t\n");
		servers[numServers].port = tok ? atoi(tok) : DEFAULT_SSH_PORT;
		if (servers[numServers].port <= 0) {
			fprintf(stderr, "Bad port number %s for server %d\n",
					tok, numServers);
			exit(-1);
		}

		numServers++;
	}
}

static void getPassword(char *password, char *host, char *user) {
	printf("Enter password for user %s: ", user);
    struct termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    struct termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    fgets(password, 128, stdin);
	password[strlen(password)-1] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	printf("\n");
}


#define checkerr2(s, args...) \
	if (s) { fprintf(stderr, args); return RECOVERABLE_ERROR; }

static int waitForNotification(int standalone) {
	PDU *response;
	char msg[256];
	if (standalone) {
		while ((! (response = readPDU(msg))) &&
			   (! strcmp(msg, TIMEOUT_TEXT))) {
			sleep(1);  // try reading from socket every 1 second
		}
		checkerr2(! response, "Error reading notification: %s\n", msg);
	} else {
		checkerr2(! (response = readPDU(msg)),
				  "Error reading notification: %s\n", msg);
	}
	checkerr2(response->pduType != PDU_SERIAL_NOTIFY,
			  "Was expecting serial notify, got %d\n", response->pduType);
	freePDU(response);
	return 0;
}


#define checkErr(s, args...) \
	if (s) { fprintf(stderr, args); return RECOVERABLE_ERROR; }

#define checkErrNon(s, args...) \
	if (s) { fprintf(stderr, args); return NONRECOVERABLE_ERROR; }

static int doResponses(PDU *request, addressBlockHandler abh,
					   clearDataHandler cdh, updateCompleteHandler uch,
					   uint *serialNumP) {
	PDU *response;
	IPPrefixData *prefixData;
	char msg[256];
	int numResponses = 0;

	checkErr(writePDU(request) < 0, "Error writing query request\n");
	checkErr(! (response = readPDU(msg)), "Error reading cache response\n");
	checkErrNon(response->pduType == PDU_ERROR_REPORT &&
				response->color == ERR_NO_DATA,
				"No data currently available at the server\n");
	checkErrNon(response->pduType == PDU_CACHE_RESET,
				"Data has become out of date at the server\n");
	checkErr(response->pduType != PDU_CACHE_RESPONSE,
			 "Was expecting cache response, got %d\n", response->pduType);
	freePDU(response);
	if (cdh) {
		checkErr((*cdh)(), "Top-level choice to quit in clearData\n");
	}
	for (response = readPDU(msg);
		 response && (response->pduType != PDU_END_OF_DATA);
		 response = readPDU(msg)) {
		prefixData = (IPPrefixData *) response->typeSpecificData;
		checkErr(response->pduType != PDU_IPV4_PREFIX &&
				 response->pduType == PDU_IPV6_PREFIX,
				 "Received unexpected pdu type %d\n", response->pduType);
		checkErr((*abh)(prefixData, response->pduType != PDU_IPV4_PREFIX,
						prefixData->flags == FLAG_ANNOUNCE),
				 "Top-level choice to quit in addrressBlock\n");
		freePDU(response);
		numResponses++;
	}
	checkErr(! response, "Missing end-of-data pdu\n");
	*serialNumP = *((uint *)response->typeSpecificData);
	freePDU(response);
	if (numResponses > 0) {
		checkErr((*uch)(), "Top-level choice to quit in updateComplete\n");
	}
	return 0;
}


#define KILL_IT {											\
	if (servers[i].standalone) sshCloseSession(session);	\
	else killSSHProcess(); }

#define NEXT_RECONNECT							\
	if (reconnectTries == maxReconnectTries) {	\
		reconnectTries = 0; break;				\
	}											\
	reconnectTries++; i--;						\
	sleep(reconnectDelay); continue;
	

#define contOnErr(s, args...) if ((s) < 0) {		   \
		fprintf(stderr, args);						   \
		KILL_IT;									   \
		if (reconnectTries == 0) continue;			   \
		NEXT_RECONNECT; }

#define breakOnErr(s, args...)											\
	err = s;															\
	if (err < 0) {														\
		fprintf(stderr, "Closing connection to host %s\n", servers[i].host); \
		if (err == NONRECOVERABLE_ERROR) reconnectTries = maxReconnectTries; \
		KILL_IT; break;													\
	}

#define MAX_ATTEMPTS 1

void runClient(addressBlockHandler abh, clearDataHandler cdh,
			   updateCompleteHandler uch, char *hostsFilename,
			   int reconnectDelay, int maxReconnectTries) {
	int i, j, reconnectTries = 0;
	PDU request;
	uint serialNum;
	CRYPT_SESSION session;

	parseServers(hostsFilename);
	while (1) {
		for (i = 0; i < numServers; i++) {
			// try connecting to server i, if fails move on to next i
			if (! servers[i].standalone) {
				contOnErr(initSSHProcess(servers[i].host, servers[i].port,
										 servers[i].user),
						  "Problem connecting to host/port %d: %s/%d\n",
						  i, servers[i].host, servers[i].port);
			} else {
				char password[128];
				contOnErr(initSSH(), "Error initializing cryptlib\n");
				for (j = 0; j < MAX_ATTEMPTS; j++) {
					getPassword(password, servers[i].host, servers[i].user);
					if (sshOpenClientSession(&session, servers[i].host,
											 servers[i].port, servers[i].user,
											 password) >= 0) {
						setSession(session);
						break;
					}
					fprintf(stderr, "Try again to connect to %s\n",
							servers[i].host);
				}
				contOnErr(MAX_ATTEMPTS - j - 1,
						  "Problem connecting to host/port %d: %s/%d\n",
						  i, servers[i].host, servers[i].port);
			}

			// try reset query for server i, if error move on to next i
			// but, if this is a reconnect attempt, instead do a serial query
			if (reconnectTries == 0) {
				fillInPDUHeader(&request, PDU_RESET_QUERY, 0);
				contOnErr(doResponses(&request, abh, cdh, uch, &serialNum),
						  "Failed during reset query for host %d: %s\n",
						  i, servers[i].host);
				request.typeSpecificData = &serialNum;
			} else {
				fillInPDUHeader(&request, PDU_SERIAL_QUERY, 0);
				contOnErr(doResponses(&request, abh, NULL, uch, &serialNum),
						  "Failed during serial query for host %d: %s\n",
						  i, servers[i].host);
				reconnectTries = 0;  // completed successfully, so reset
				fprintf(stderr, "Re-established connection to host %d: %s\n",
						i, servers[i].host);
			}

			// then, go into loop where wait for notification and then
			//   issue a serial query and handle the results
			while (1) {
				int err;
				breakOnErr(waitForNotification(servers[i].standalone));
				fillInPDUHeader(&request, PDU_SERIAL_QUERY, 0);
				breakOnErr(doResponses(&request, abh, NULL, uch, &serialNum));
			}
			NEXT_RECONNECT;
		}
		if (i == numServers) {
			fprintf(stderr, "Failed on all servers, trying again\n");
			sleep(reconnectDelay);
		} else {
			fprintf(stderr, "Failure on host %s, trying from start\n",
					servers[i].host);
		}
	}
}

