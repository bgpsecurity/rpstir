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
 * Copyright (C) Raytheon BBN Technologies Corp. 2007.  All Rights Reserved.
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

#ifndef _RTR_PDU_H
#define _RTR_PDU_H

#include <stdint.h>
#include <stddef.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "macros.h"

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
#define FLAG_WITHDRAW_ANNOUNCE 0x1
#define FLAGS_RESERVED (0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x80)

/*****
 * Error types for error report pdu's
 *****/
#define ERR_CORRUPT_DATA 0
#define ERR_INTERNAL_ERROR 1
#define ERR_NO_DATA 2
#define ERR_INVALID_REQUEST 3
#define ERR_UNSUPPORTED_VERSION 4
#define ERR_UNSUPPORTED_TYPE 5
#define ERR_UNKNOWN_WITHDRAW 6
#define ERR_DUPLICATE_ANNOUNCE 7


typedef uint16_t cache_nonce_t;
typedef uint32_t serial_number_t;


struct _PDU;
typedef struct _PDU PDU;

/*****
 * structures holding data for an IP prefix (v4 or v6)
 *****/
typedef struct _IP4PrefixData {
	uint8_t flags;
	uint8_t prefixLength;
	uint8_t maxLength;
	uint8_t reserved;
	struct in_addr prefix4;
	uint32_t asNumber;
} PACKED_STRUCT IP4PrefixData;

typedef struct _IP6PrefixData {
	uint8_t flags;
	uint8_t prefixLength;
	uint8_t maxLength;
	uint8_t reserved;
	struct in6_addr prefix6;
	uint32_t asNumber;
} PACKED_STRUCT IP6PrefixData;

/*****
 * structure holding the data for an error response
 *****/
typedef struct _ErrorData {
	uint32_t encapsulatedPDULength;
	PDU *encapsulatedPDU;
	uint32_t errorTextLength;
	uint8_t *errorText;
} ErrorData;

/*****
 * Basic structure of a PDU
 *****/
struct _PDU {
	uint8_t protocolVersion;
	uint8_t pduType;
	union {
		cache_nonce_t cacheNonce;
		uint16_t reserved;
		uint16_t errorCode;
	};
	uint32_t length;
	union {
		serial_number_t serialNumber;
		IP4PrefixData ip4PrefixData;
		IP6PrefixData ip6PrefixData;
		ErrorData errorData;
	};
} PACKED_STRUCT;

#define PDU_HEADER_LENGTH (offsetof(PDU, serialNumber))


#endif
