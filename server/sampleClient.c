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

#include "coreClient.h"

/* just a simple example of how to write callback */
static int printAssignData(IPPrefixData data, int isIPV4, int isAnnounce) {
	// printf
	return 0;
}

/* just a simple example of how to write callback */
static int printReset() {
	return 0;
}

int main(int argc, char **argv) {
	runClient(printAssignData, printReset, "sampleHostsFile", 5, 10);
	return 0;
}
