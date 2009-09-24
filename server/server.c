/************************
 * Server that implements RTR protocol
 ***********************/

#include "pdu.h"
#include "socket.h"
#include <stdio.h>

int main(int argc, char **argv) {
	int sock;
	PDU *request, response;

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
	fillInPDUHeader(&response, PDU_END_OF_DATA, 1);
	if (writePDU(&response, sock) == -1) {
		printf("Error writing end of data\n");
		return -1;
	}
	printf("Completed successfully\n");
	return 1;
}
