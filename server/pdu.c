/****************
 * The code for sending and receiving Protocol Data Units (PDUs)
 *    between server and clients
 ***************/

#include "pdu.h"
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>


/****** ???????????????? need to send error pdu's ???????????? *****/

#define CHECK_LEN(s) \
	if (pdu->length != (s)) {  \
		printf("Error: was expecting length %d not %d for pdu type %d\n", \
			   (s), pdu->length, pdu->pduType);	 \
		freePDU(pdu); \
		return NULL; \
	}

#define CHECK_READ(s) \
	if ((s) <= 0) { \
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

PDU *readPDU(int sock) {
	PDU *pdu = calloc(1, sizeof(PDU));
	IPPrefixData *prefixData;
	uint *serialNum, i;

	// receive header
	READ_BYTE(pdu->protocolVersion);
	READ_BYTE(pdu->pduType);
	READ_SHORT(pdu->color);
	READ_INT(pdu->length);

	// receive type-specific data
	switch (pdu->pduType) {
	case PDU_RESET_QUERY:
	case PDU_CACHE_RESPONSE:
	case PDU_CACHE_RESET:
		CHECK_LEN(8);
		return pdu;
	case PDU_SERIAL_NOTIFY:
	case PDU_SERIAL_QUERY:
	case PDU_END_OF_DATA:
		CHECK_LEN(12);
		serialNum = malloc(sizeof(uint));
		pdu->typeSpecificData = serialNum;
		READ_INT(i);
		*serialNum = i;
		return pdu;
	case PDU_IPV4_PREFIX:
	case PDU_IPV6_PREFIX:
		CHECK_LEN((pdu->pduType == PDU_IPV4_PREFIX) ? 20 : 40);
		prefixData = calloc(1, sizeof(IPPrefixData));
		pdu->typeSpecificData = prefixData;
		READ_BYTE(prefixData->flags);
		READ_BYTE(prefixData->prefixLength);
		READ_BYTE(prefixData->maxLength);
		READ_BYTE(prefixData->dataSource);
		for (i = 0; i < ((pdu->pduType == PDU_IPV4_PREFIX) ? 1 : 4); i++) {
			READ_INT(prefixData->ipPrefix[i]);
		}
		READ_INT(prefixData->asNumber);
		return pdu;
	}

	// handle case with unknown type
	freePDU(pdu);
	printf ("Unknown pdu type %d received\n", pdu->pduType);
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
	uchar buffer[4];
	uint i;

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
			WRITE_INT(prefixData->ipPrefix[i]);
		}
		WRITE_INT(prefixData->asNumber);
		return 1;
	}

	return 0;
}


void freePDU(PDU *pdu) {
	if (pdu->typeSpecificData) free(pdu->typeSpecificData);
	free(pdu);
}

