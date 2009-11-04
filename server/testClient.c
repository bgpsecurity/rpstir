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


#define checkSSH(s, args...) if ((s) < 0) { printf(args); return -1; }

int main(int argc, char **argv) {
	CRYPT_SESSION session;
	PDU request, *response;
	char msg[256];

	checkSSH(initSSH(), "Error initializing SSH\n");

	printf("\nDoing reset query\n");
	checkSSH(sshOpenClientSession(&session, "localhost"),
			 "Error opening client session\n");
	setSession(session);
	fillInPDUHeader(&request, PDU_RESET_QUERY, 1);
	checkSSH(writePDU(&request), "Error writing reset query\n");
	checkSSH(readResponses(), "Failed on reset query\n");
	sshCloseSession(session);

	printf("\n\nDoing serial query\n");
	checkSSH(sshOpenClientSession(&session, "localhost"),
			 "Error opening client session\n");
	setSession(session);
	fillInPDUHeader(&request, PDU_SERIAL_QUERY, 1);
	*((uint *) request.typeSpecificData) = 1;
	checkSSH(writePDU(&request), "Error writing serial query\n");
	checkSSH(readResponses(), "Failed on serial query\n");
	sshCloseSession(session);

	printf("\nDoing serial query with reset response\n");
	checkSSH(sshOpenClientSession(&session, "localhost"),
			 "Error opening client session\n");
	setSession(session);
	*((uint *) request.typeSpecificData) = 8723;
	checkSSH(writePDU(&request), "Error writing serial query\n");
	if (! (response = readPDU(msg))) {
		printf ("Error reading cache reset\n");
		return -1;
	}
	if (response->pduType != PDU_CACHE_RESET) {
		printf ("Was expecting cache reset, got %d\n", response->pduType);
		return -1;
	}
	sshCloseSession(session);
	freePDU(response);

	printf("\nDoing illegal request\n");
	checkSSH(sshOpenClientSession(&session, "localhost"),
			 "Error opening client session\n");
	setSession(session);
	fillInPDUHeader(&request, PDU_END_OF_DATA, 1);
	checkSSH(writePDU(&request), "Error writing end of data\n");
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
	sshCloseSession(session);

	printf("Completed successfully\n");
	return 1;
}
