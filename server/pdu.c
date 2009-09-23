/****************
 * The code for sending and receiving Protocol Data Units (PDUs)
 *    between server and clients
 ***************/

#include "pdu.h"
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

#define CHECK_ERR(s) if (! (s)) { freePDU(pdu); return NULL; }

#define CHECK_LEN(s) if (pdu->length != (s)) { \\
	printf("Error: was expecting length %d not %d for pdu type %d\n", \\
		   (s), pdu->length, pdu->pduType); \\
	freePDU(pdu); return NULL; }

PDU *readPDU(int sock) {
	// receive header
	PDU *pdu = calloc(1, sizeof(PDU));
	IPPrefixData *prefixData;
	CHECK_ERR (recv(sock, &(pdu->protocolVersion), 1, 0));
	CHECK_ERR (recv(sock, &(pdu->pduType), 1, 0));
	CHECK_ERR (recv(sock, &(pdu->color), 2, 0));
	pdu->color = ntohs(pdu->color);
	CHECK_ERR (recv(sock, &(pdu->length), 4, 0));
	pdu->length = ntohl(pdu->length);

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
		// ???????????? read serial number ???????????
		return pdu;
	case PDU_IPV4_PREFIX:
	case PDU_IPV6_PREFIX:
		CHECK_LEN((pdu->pduType == PDU_IPV4_PREFIX) ? 20 : 40);
		prefixData = calloc(1, sizeof(IPPrefixData));
		pdu->typeSpecificData = prefixData;
		CHECK_ERR (recv(sock, &(prefixData->flags), 1, 0));
		CHECK_ERR (recv(sock, &(prefixData->prefixLength), 1, 0));
		CHECK_ERR (recv(sock, &(prefixData->maxLength), 1, 0));
		CHECK_ERR (recv(sock, &(prefixData->dataSource), 1, 0));
		// ?????? read the prefix ?????????????
		CHECK_ERR (recv(sock, &(prefixData->asNumber), 4, 0));
		prefixData->asNumber = ntohl(prefixData->asNumber);
		return pdu;
	}
	freePDU(pdu);
	printf ("Unknown pdu type %d received\n", pdu->pduType);
	return NULL;
}

void freePDU(PDU *pdu) {
	if (pdu->typeSpecificData) free(pdu->typeSpecificData);
	free(pdu);
}

