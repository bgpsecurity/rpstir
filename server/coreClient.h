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

#include "pdu.h"

/************************
 * Performs the basic functionality of the client,
 * The caller needs just specify some parameters and callbacks that
 *   handle the data as it is returned
 ***********************/

/******
 * Prototype for the callback functions for handling data
 * Argument: data - This contains all the data on the address block and
 *   the autonomous system number, etc; note that this structure is
 *   transient, and the data should be copied out
 * Argument: isIPV4 - true for IPV4, false for IPV6
 * Argument: isAnnounce - 0 if withdrawal, !=0 if is announcement
 * Returning a value <0 causes the core client to stop
 ******/
typedef int (*addressBlockHandler)(IPPrefixData *data, int isIPV4,
								   int isAnnounce);

/******
 * Prototype for the callback functions for switching servers, and
 *   hence for starting a fresh new set of address block assignments
 * Returning a value <0 causes the core client to stop
 ******/
typedef int (*clearDataHandler)(void);

/******
 * Function for running the client
 * Argument: hostsFilename - Full path of file containing the list of servers
 * Argument: reconnectDelay - Number of seconds to wait between tries to
 *                            re-establish connectivity to the current server
 * Argument: maxReconnectTries - Number of times to try reconnecting before
 *                               giving up and going back to the server list
 * Note that going back to the server list and starting from the top to
 *   try to find a connection means abandoning the current incremental
 *   state and doing a full (reset) read of all the data; therefore, it
 *   is good to have some patience with a server before giving up on it.
 * Note if a server loses its ability to provide incremental updates,
 *   this routine goes back to the head of the list, since if it needs
 *   to start from scratch, it may as well do so with the more preferable
 *   server
 ******/
void runClient(addressBlockHandler abh, clearDataHandler cdh,
			   char *hostsFilename, int reconnectDelay,
			   int maxReconnectTries);
