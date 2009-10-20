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
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>


#define CHECK_READ(s) \
	if ((s) <= 0) { \
		snprintf(errMsg, 128, "Badly formatted PDU\n"); \
		freePDU(pdu); \
		return NULL; \
	}

#define READ_BYTE(b) CHECK_READ(recv(sock, &(b), 1, 0))

#define READ_SHORT(i) { \
	CHECK_READ(recv(sock, &(i), 2, 0)); \
	i = ntohs(i); }

#define READ_INT(i) { \
	CHECK_READ(recv(sock, &(i), 4, 0)); \
	i = ntohl(i); }

PDU *readPDU(int sock, char *errMsg) {
	PDU *pdu = calloc(1, sizeof(PDU));
	IPPrefixData *prefixData;
	ErrorData *errorData;
	uint *serialNum, i, len;
	int expectedLen;

	// receive header and check length
	READ_BYTE(pdu->protocolVersion);
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
		errorData->badPDU = readPDU(sock, errMsg);
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


#define CHECK_WRITE(s) if ((s) <= 0) return 0;

#define WRITE_BYTE(b) CHECK_WRITE(send(sock, &(b), 1, 0));

#define WRITE_SHORT(i) { \
	*((short *) buffer) = htons(i); \
	CHECK_WRITE(send(sock, buffer, 2, 0)); }

#define WRITE_INT(i) { \
	*((uint *) buffer) = htonl(i); \
	CHECK_WRITE(send(sock, buffer, 4, 0)); }

int writePDU(PDU *pdu, int sock) {
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
		return 1;
	case PDU_SERIAL_NOTIFY:
	case PDU_SERIAL_QUERY:
	case PDU_END_OF_DATA:
		i = *((uint *) pdu->typeSpecificData);
		WRITE_INT(i);
		return 1;
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
		return 1;
	case PDU_ERROR_REPORT:
		errorData = (ErrorData *) pdu->typeSpecificData;
		if (! errorData->badPDU) {
			WRITE_INT(0);
		} else {
			WRITE_INT(errorData->badPDU->length);
			if (! writePDU(errorData->badPDU, sock)) return 0;
		}
		WRITE_INT(strlen(errorData->errorText));
		for (i = 0; i < strlen(errorData->errorText); i++) {
			WRITE_BYTE(errorData->errorText[i]);
		}
		return 1;
	}

	return 0;
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