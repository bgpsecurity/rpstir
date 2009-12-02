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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "coreClient.h"

typedef struct _ServerInfo {
	char *host;
	int port;
	char standalone;   // should client connect directly or via SSH client
} ServerInfo;

#define MAX_SERVERS 64
static ServerInfo servers[MAX_SERVERS];
static int numServers = 0;

#define STR_SIZE 256
static void parseServers (char *filename) {
	char str[STR_SIZE], str2[STR_SIZE], str3[STR_SIZE];
	FILE *input = fopen (filename, "r");

	if (input == NULL) {
		fprintf (stderr, "Could not open server hosts file: %s\n", filename);
		exit(-1);
	}
	while (fgets (str, STR_SIZE, input)) {
		int got = sscanf(str, "%s %s", str2, str3);
		if (got == 0) continue;
		if (numServers >= MAX_SERVERS) {
			fprintf(stderr, "Number of servers greater than max: %d\n",
					MAX_SERVERS);
			exit(-1);
		}
		servers[numServers].host = strdup(str2);
		// ???????????? what about port and standalone ????????
		numServers++;
	}
}

void runClient(addressBlockHandler abh, clearDataHandler cdh,
			   char *hostsFilename, int reconnectDelay,
			   int maxReconnectTries) {
	parseServers(hostsFilename);
}

