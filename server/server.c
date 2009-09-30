/************************
 * Server that implements RTR protocol
 ***********************/

#include "pdu.h"
#include "socket.h"
#include <stdio.h>

int main(int argc, char **argv) {
	int sock;
	PDU *request, response;
	IPPrefixData prefixData;

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
	fillInPDUHeader(&response, PDU_IPV4_PREFIX, 0);
	response.typeSpecificData = &prefixData;
	prefixData.flags = FLAG_ANNOUNCE;
	prefixData.prefixLength = 24;
	prefixData.maxLength = 32;
	prefixData.dataSource = SOURCE_RPKI;
	prefixData.ipPrefix[0] = 12345;
	prefixData.asNumber = 45;
	if (writePDU(&response, sock) == -1) {
		printf("Error writing ipv4 prefix\n");
		return -1;
	}
	fillInPDUHeader(&response, PDU_IPV6_PREFIX, 0);
	prefixData.ipPrefix[1] = 12346;
	prefixData.ipPrefix[2] = 12347;
	prefixData.ipPrefix[3] = 12348;
	if (writePDU(&response, sock) == -1) {
		printf("Error writing ipv6 prefix\n");
		return -1;
	}
	fillInPDUHeader(&response, PDU_END_OF_DATA, 1);
	if (writePDU(&response, sock) == -1) {
		printf("Error writing end of data\n");
		return -1;
	}
	printf("Completed successfully\n");
	return 1;
}
