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
 ***********************/

#include "pdu.h"
#include "sshComms.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static int getBits(uint val, uint start, uint len) {
	return (val << start) >> (32 - len);
}

static int readResponses() {
	PDU *response;
	int i;
	IPPrefixData *prefixData;
	char msg[256];

	if (! (response = readPDU(msg))) {
		printf ("Error reading cache response\n");
		return -1;
	}
	if (response->pduType != PDU_CACHE_RESPONSE) {
		printf ("Was expecting cache response, got %d\n", response->pduType);
		return -1;
	}
	freePDU(response);
	for (response = readPDU(msg);
		 response && (response->pduType != PDU_END_OF_DATA);
		 response = readPDU(msg)) {
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
	if (! response) {
		printf ("Missing end-of-data pdu\n");
		return -1;
	}
	freePDU(response);
	return 0;
}


#define checkerr(s, args...) if ((s) < 0) { fprintf(stderr, args); exit(-1); }

static void initStandalone(char *user, char *passwd) {
	// get username and password
	printf("Enter username: ");
    fgets(user, 128, stdin);
	user[strlen(user)-1] = 0;
	printf("Enter password: ");
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

/*****
 * set up child process, set up pipes to have the parent able to
 *   write to stdin of child and read from stdout, and have the child
 *   run ssh while the parent returns after setting these pipes as
 *   those used by the PDU reading and writing routines
 *****/
static void initSSHProcess(char *host) {
	int writepipe[2] = {-1,-1}, readpipe[2] = {-1,-1};
	pid_t childpid;
	checkerr(pipe(readpipe) < 0  ||  pipe(writepipe) < 0,
			 "Cannot create pipes\n");
	checkerr(childpid = fork(), "Cannot fork child\n");
	if ( childpid == 0 ) { /* in the child */
		close(writepipe[1]);
		close(readpipe[0]);
		dup2(writepipe[0], STDIN_FILENO);  close(writepipe[0]);
		dup2(readpipe[1], STDOUT_FILENO);  close(readpipe[1]);
		char cmd[256];
		snprintf(cmd, sizeof(cmd), "ssh -s %s rpki-rtr\n", host);
		system(cmd);
	}
	else { /* in the parent */
		close(readpipe[1]);
		close(writepipe[0]);
		setPipes(readpipe[0], writepipe[1]);
	}
}

int main(int argc, char **argv) {
	CRYPT_SESSION session;
	PDU request, *response;
	char msg[256], *host = "localhost";
	int i, standalone = 0, port = DEFAULT_SSH_PORT;
	int diffPort = 0;    // indicates whether standalone server
	char user[128], passwd[128];

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

	if (standalone) initStandalone(user, passwd);
	else initSSHProcess(host);

	printf("\nDoing reset query\n");
	if (standalone) doOpen(&session, host, port, user, passwd);
	fillInPDUHeader(&request, PDU_RESET_QUERY, 1);
	checkerr(writePDU(&request), "Error writing reset query\n");
	checkerr(readResponses(), "Failed on reset query\n");
	if (standalone && diffPort) sshCloseSession(session);

	printf("\n\nDoing serial query\n");
	if (standalone && diffPort) doOpen(&session, host, port, user, passwd);
	fillInPDUHeader(&request, PDU_SERIAL_QUERY, 1);
	*((uint *) request.typeSpecificData) = 1;
	checkerr(writePDU(&request), "Error writing serial query\n");
	checkerr(readResponses(), "Failed on serial query\n");
	if (standalone && diffPort) sshCloseSession(session);

	printf("\nDoing serial query with reset response\n");
	if (standalone && diffPort) doOpen(&session, host, port, user, passwd);
	*((uint *) request.typeSpecificData) = 8723;
	checkerr(writePDU(&request), "Error writing serial query\n");
	if (! (response = readPDU(msg))) {
		printf ("Error reading cache reset\n");
		return -1;
	}
	if (response->pduType != PDU_CACHE_RESET) {
		printf ("Was expecting cache reset, got %d\n", response->pduType);
		return -1;
	}
	if (standalone && diffPort) sshCloseSession(session);
	freePDU(response);

	printf("\nDoing illegal request\n");
	if (standalone && diffPort) doOpen(&session, host, port, user, passwd);
	fillInPDUHeader(&request, PDU_END_OF_DATA, 1);
	checkerr(writePDU(&request), "Error writing end of data\n");
	if (! (response = readPDU(msg))) {
		printf ("Error reading error report\n");
		return -1;
	}
	if (response->pduType != PDU_ERROR_REPORT) {
		printf ("Was expecting error report, got %d\n", response->pduType);
		return -1;
	}
	printf("Error text = %s\n",
		   ((ErrorData *)response->typeSpecificData)->errorText);
	if (standalone && diffPort) sshCloseSession(session);

	printf ("Waiting for change notification\n");
	if (! (response = readPDU(msg))) {
		printf ("Error reading change notification\n");
		return -1;
	}
	if (response->pduType != PDU_SERIAL_NOTIFY) {
		printf ("Was expecting error report, got %d\n", response->pduType);
		return -1;
	}
	printf("Received change notification\n\n");

	printf("Completed successfully\n");
	return 1;
}
