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

/****************
 * The code for sending and receiving Protocol Data Units (PDUs)
 *    between server and clients
 ***************/

#include "pdu.h"
#include "sshComms.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

// global variables
CRYPT_SESSION session;
uchar sessionSet = 0;
int readPipe = STDIN_FILENO, writePipe = STDOUT_FILENO;

void setSession(CRYPT_SESSION s) {
	session = s; sessionSet = 1;
}

void setPipes(int rp, int wp) {
	readPipe = rp; writePipe = wp;
}

/*****************
 * macros for reading
 ****************/

#define DO_READ(_loc, _sz)								\
	if ((sessionSet ?									\
		 sshReceive(session, &(_loc), _sz) :			\
		 read(readPipe, &(_loc), _sz)) <= 0) {			\
		snprintf(errMsg, 128, "Badly formatted PDU\n"); \
		freePDU(pdu);									\
		return NULL;									\
	}

#define READ_BYTE(b) DO_READ(b, 1)

#define READ_SHORT(i) { DO_READ(i, 2); i = ntohs(i); }

#define READ_INT(i) { DO_READ(i, 4); i = ntohl(i); }


PDU *readPDU(char *errMsg) {
	return readPduAndLock(errMsg, NULL);
}

PDU *readPduAndLock(char *errMsg, pthread_mutex_t *mutex) {
	PDU *pdu = calloc(1, sizeof(PDU));
	IPPrefixData *prefixData;
	ErrorData *errorData;
	uint *serialNum, i, len;
	int expectedLen;

	// receive header and check length
	READ_BYTE(pdu->protocolVersion);
	if (mutex) pthread_mutex_lock(mutex);
	READ_BYTE(pdu->pduType);
	READ_SHORT(pdu->color);
	READ_INT(pdu->length);
	expectedLen = lengthForType(pdu->pduType);
	if ((expectedLen != -1) && (pdu->length != expectedLen)) {
		snprintf(errMsg, 128,
				 "Error: was expecting length %d not %d for pdu type %d\n",
				 expectedLen, pdu->length, pdu->pduType);	
		freePDU(pdu);
		return NULL;
	}

	// receive type-specific data
	switch (pdu->pduType) {
	case PDU_RESET_QUERY:
	case PDU_CACHE_RESPONSE:
	case PDU_CACHE_RESET:
		return pdu;
	case PDU_SERIAL_NOTIFY:
	case PDU_SERIAL_QUERY:
	case PDU_END_OF_DATA:
		serialNum = malloc(sizeof(uint));
		pdu->typeSpecificData = serialNum;
		READ_INT(i);
		*serialNum = i;
		return pdu;
	case PDU_IPV4_PREFIX:
	case PDU_IPV6_PREFIX:
		prefixData = calloc(1, sizeof(IPPrefixData));
		pdu->typeSpecificData = prefixData;
		READ_BYTE(prefixData->flags);
		READ_BYTE(prefixData->prefixLength);
		READ_BYTE(prefixData->maxLength);
		READ_BYTE(prefixData->dataSource);
		for (i = 0; i < ((pdu->pduType == PDU_IPV4_PREFIX) ? 1 : 4); i++) {
			READ_INT(prefixData->ipAddress[i]);
		}
		READ_INT(prefixData->asNumber);
		return pdu;
	case PDU_ERROR_REPORT:
		errorData = calloc(1, sizeof(ErrorData));
		pdu->typeSpecificData = errorData;
		READ_INT(len);
		errorData->badPDU = readPDU(errMsg);
		if ((! errorData->badPDU) || (errorData->badPDU->length != len)) {
			snprintf(errMsg, 128, "Bad PDU length in error reply\n");
			freePDU(pdu);
			return NULL;
		}
		READ_INT(len);
		errorData->errorText = malloc(len+1);
		for (i = 0; i < len; i++) {
			READ_BYTE(errorData->errorText[i]);
		}
		errorData->errorText[len] = 0;
		if (pdu->length != (16 + errorData->badPDU->length + len)) {
			printf("Lengths not consistent in error report PDU\n");
		}
		return pdu;
	}

	// handle case with unknown type
	snprintf(errMsg, 128, "Unknown pdu type %d received\n", pdu->pduType);
	freePDU(pdu);
	return NULL;
}


/*****************
 * macros for writing
 ****************/

#define DO_WRITE(_ptr, _sz)									\
	{ if ((sessionSet ?										\
		   sshCollect(session, _ptr, _sz) :					\
		   write(writePipe,_ptr, _sz)) <= 0) return -1; }

#define WRITE_BYTE(b) DO_WRITE(&(b), 1)

#define WRITE_SHORT(i) { *((short *) buffer) = htons(i); DO_WRITE(buffer, 2) }

#define WRITE_INT(i) { *((uint *) buffer) = htonl(i); DO_WRITE(buffer, 4) }


static int writePDU2(PDU *pdu, int topLevel) {
	IPPrefixData *prefixData;
	ErrorData *errorData;
	uchar buffer[4];
	uint i;

	// get length set correctly for error reports
	if (pdu->pduType == PDU_ERROR_REPORT) {
		errorData = (ErrorData *) pdu->typeSpecificData;
		pdu->length = 16 + strlen(errorData->errorText) +
			(errorData->badPDU ? errorData->badPDU->length: 0);
	}

	// send header
	WRITE_BYTE(pdu->protocolVersion);
	WRITE_BYTE(pdu->pduType);
	WRITE_SHORT(pdu->color);
	WRITE_INT(pdu->length);

	// send type-specific data
	switch (pdu->pduType) {
	case PDU_RESET_QUERY:
	case PDU_CACHE_RESPONSE:
	case PDU_CACHE_RESET:
		break;
	case PDU_SERIAL_NOTIFY:
	case PDU_SERIAL_QUERY:
	case PDU_END_OF_DATA:
		i = *((uint *) pdu->typeSpecificData);
		WRITE_INT(i);
		break;
	case PDU_IPV4_PREFIX:
	case PDU_IPV6_PREFIX:
		prefixData = (IPPrefixData *) pdu->typeSpecificData;
		WRITE_BYTE(prefixData->flags);
		WRITE_BYTE(prefixData->prefixLength);
		WRITE_BYTE(prefixData->maxLength);
		WRITE_BYTE(prefixData->dataSource);
		for (i = 0; i < ((pdu->pduType == PDU_IPV4_PREFIX) ? 1 : 4); i++) {
			WRITE_INT(prefixData->ipAddress[i]);
		}
		WRITE_INT(prefixData->asNumber);
		break;
	case PDU_ERROR_REPORT:
		errorData = (ErrorData *) pdu->typeSpecificData;
		if (! errorData->badPDU) {
			WRITE_INT(0);
		} else {
			WRITE_INT(errorData->badPDU->length);
			if (writePDU2(errorData->badPDU, 0) < 0) return -1;
		}
		WRITE_INT(strlen(errorData->errorText));
		for (i = 0; i < strlen(errorData->errorText); i++) {
			WRITE_BYTE(errorData->errorText[i]);
		}
		break;
	}

	if (topLevel) {
		if (sessionSet) {
			if (sshSendCollected(session) < 0) return -1;
		} else {
			//flush(writePipe);
		}
	}
	return 0;
}

int writePDU(PDU *pdu) {
	return writePDU2(pdu, 1);
}

void freePDU(PDU *pdu) {
	if (pdu->typeSpecificData) {
		free(pdu->typeSpecificData);
		if (pdu->pduType == PDU_ERROR_REPORT) {
			ErrorData *errData = (ErrorData *)pdu->typeSpecificData;
			if (errData->badPDU) freePDU(errData->badPDU);
			if (errData->errorText) free(errData->errorText);
		}
	}
	free(pdu);
}

void fillInPDUHeader(PDU *pdu, uchar pduType, char allocRest) {
	pdu->protocolVersion = PROTOCOL_VERSION;
	pdu->pduType = pduType;
	pdu->color = 0;
	pdu->length = lengthForType(pduType);
	if (allocRest) {
		pdu->typeSpecificData = NULL;
		switch (pduType) {
		case PDU_SERIAL_NOTIFY: case PDU_SERIAL_QUERY: case PDU_END_OF_DATA:
			pdu->typeSpecificData = malloc(sizeof(uint));
			break;
		case PDU_IPV4_PREFIX: case PDU_IPV6_PREFIX:
			pdu->typeSpecificData = calloc(1, sizeof(IPPrefixData));
			break;
		case PDU_ERROR_REPORT:
			pdu->typeSpecificData = calloc(1, sizeof(ErrorData));
		}
	}
}

int lengthForType(uchar pduType) {
	switch (pduType) {
	case PDU_RESET_QUERY: case PDU_CACHE_RESPONSE: case PDU_CACHE_RESET:
		return 8;
	case PDU_SERIAL_NOTIFY: case PDU_SERIAL_QUERY: case PDU_END_OF_DATA:
		return 12;
	case PDU_IPV4_PREFIX:
		return 20;
	case PDU_IPV6_PREFIX:
		return 40;
	}
	return -1;
}
