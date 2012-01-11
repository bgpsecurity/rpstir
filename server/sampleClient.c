
/*
  $Id: query.c 857 2009-09-30 15:27:40Z dmontana $
*/

#include "coreClient.h"
#include <stdio.h>
#include <stdlib.h>

static int getBits(uint val, uint start, uint len) {
	return (val << start) >> (32 - len);
}

/* just a simple example of how to write callback */
static int printAssignData(IPPrefixData *data, int isIPV4, int isAnnounce) {
	int i;
	fprintf (stderr, "%s as# = %d len = %d max = %d addr = ",
			 (data->flags == FLAG_ANNOUNCE) ? "ANNOUNCE" : "WITHDRAW",
			 data->asNumber, data->prefixLength, data->maxLength);
	if (isIPV4) {
		for (i = 0; i < 4; i++)
			fprintf(stderr, "%d%s", getBits(data->ipAddress[0], 8*i, 8),
					(i == 3) ? "\n" : ".");
	} else {
		for (i = 0; i < 8; i++)
			fprintf(stderr, "%x%s",
					getBits(data->ipAddress[i/2], (i%2)*16, 16),
					(i == 7) ? "\n" : ":");
	}
	return 0;
}

static int printDataDone() {
	fprintf(stderr, "This set of data is now complete.\n\n\n");
	return 0;
}

static int firstReset = 1;

/* just a simple example of how to write callback */
static int printReset() {
	fprintf(stderr, firstReset ?
			"\n\nInitial connection\n" :
			"\n\nServer failed, clear all data and start again.\n");
	return 0;
}

int main(int argc, char **argv) {
	runClient(printAssignData, printReset, printDataDone,
			  "sampleHostsFile", 5, 2);
	return 0;
}
