/************************
 * Sample client for the purposes of testing and demonstrating
 *   use of the library
 ***********************/

#include "pdu.h"
#include "socket.h"

int main(int argc, char **argv) {
	int sock;
	PDU request, *response;

	if ((sock = getClientSocket("localhost")) == -1) {
		printf ("Error opening socket\n");
		return -1;
	}
	fillInPDUHeader(&request, PDU_RESET_QUERY, 1);
	if (writePDU(&request, sock)) {
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
}
