/************************
 * Sample client for the purposes of testing and demonstrating
 *   use of the library
 ***********************/

#include "pdu.h"
#include "socket.h"
#include <stdio.h>

int main(int argc, char **argv) {
	int sock;
	PDU request, *response;

	if ((sock = getClientSocket("localhost")) == -1) {
		printf ("Error opening socket\n");
		return -1;
	}
	fillInPDUHeader(&request, PDU_RESET_QUERY, 1);
	if (writePDU(&request, sock) == -1) {
		printf ("Error writing reset query\n");
		return -1;
	}
	if (! (response = readPDU(sock))) {
		printf ("Error reading cache response\n");
		return -1;
	}
	if (response->pduType != PDU_CACHE_RESPONSE) {
		printf ("Was expecting cache response, got %d\n", response->pduType);
		return -1;
	}
	for (response = readPDU(sock);
		 response && (response->pduType != PDU_END_OF_DATA);
		 response = readPDU(sock)) {
		if (response->pduType == PDU_IPV4_PREFIX) {
			printf ("Received pdu of type IPv4 prefix\n");
		} else if (response->pduType == PDU_IPV6_PREFIX) {
			printf ("Received pdu of type IPv4 prefix\n");
		} else {
			printf ("Received unexpected pdu type %d", response->pduType);
			return -1;
		}
	}
	if (! response) {
		printf ("Missing end-of-data pdu\n");
		return -1;
	}
	printf("Completed successfully\n");
	return 1;
}
