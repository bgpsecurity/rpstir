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

/****************
 * The code for sending and receiving Protocol Data Units (PDUs)
 *    between server and clients
 ***************/

#ifndef _PDU_H
#define _PDU_H

#include <cryptlib.h>
#include <pthread.h>

/*****
 * Different PDU types
 *****/
#define PDU_SERIAL_NOTIFY 0
#define PDU_SERIAL_QUERY 1
#define PDU_RESET_QUERY 2
#define PDU_CACHE_RESPONSE 3
#define PDU_IPV4_PREFIX 4
#define PDU_IPV6_PREFIX 6
#define PDU_END_OF_DATA 7
#define PDU_CACHE_RESET 8
#define PDU_ERROR_REPORT 10

/*****
 * Constants for use in the PDUs
 *****/
#define PROTOCOL_VERSION 0
#define SOURCE_RPKI 0
#define SOURCE_IRR 1
#define FLAG_WITHDRAW 0
#define FLAG_ANNOUNCE 1

/*****
 * Error types for error report pdu's
 *****/
#define ERR_INTERNAL_ERROR 1
#define ERR_NO_DATA 2
#define ERR_INVALID_REQUEST 3

typedef unsigned char uchar;
typedef unsigned int uint;

/*****
 * Basic structure of a PDU
 *****/
typedef struct _PDU {
	uchar protocolVersion;
	uchar pduType;
	short color;
	uint length;
	void *typeSpecificData;
} PDU;

/*****
 * structure holding data for an IP prefix (v4 or v6)
 *****/
typedef struct _IPPrefixData {
	uchar flags;
	uchar prefixLength;
	uchar maxLength;
	uchar dataSource;
	uint ipAddress[4];    // for ipv4, only use first entry
	uint asNumber;
} IPPrefixData;

/*****
 * structure holding the data for an error response
 *****/
typedef struct _ErrorData {
	PDU *badPDU;
	char *errorText;
} ErrorData;

/*****
 * if using an SSH session for comms, indicate it by calling this function
 * if using stdin/stdout for comms, do not call this function
 *****/
void setSession(CRYPT_SESSION session);

/*****
 * if using pipes for comms and want to specify other pipes besides
 *   stdin and stdout, call this function
 *****/
void setPipes(int readPipe, int writePipe);

/*****
 * read a PDU from the SSH session, waiting until there is data on the socket
 *   returns a NULL PDU on error
 * Arg: errMsg - provide a buffer where any error message can be returned
 * Arg: mutex - if non-NULL, lock this mutex after receiving the first byte
 * Remember to free the PDU returned when done with it
 *****/
PDU *readPDU(char *errMsg);

/*****
 * same as readPDU, except also set a lock on the mutex, if the mutex
 *   is non-NULL, after receiving the first byte of data
 *****/
PDU *readPduAndLock(char *errMsg, pthread_mutex_t *mutex);

/*****
 * write a PDU to the SSH session, returning a non-zero value for an error
 *****/
int writePDU(PDU *pdu);

/*****
 * free a PDU returned from readPDU (does a deep free)
 *****/
void freePDU(PDU *pdu);

/*****
 * fill in the header portion of a PDU given its type,
 *   optionally allocating memory for the type-specific portion
 *****/
void fillInPDUHeader(PDU *pdu, uchar pduType, char allocRest);

/*****
 * utility routine that gives the expected length for a given type
 *****/
int lengthForType(uchar pduType);

#endif
