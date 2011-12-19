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
#define RTR_PROTOCOL_VERSION 0
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
#define ERR_IS_FATAL(code) \
	((code) != ERR_NO_DATA)

/**
	NOTE: all values in structs are stored in host byte order.
	The functions parse_pdu and dump_pdu will handle byte order issues.
*/

typedef uint16_t cache_nonce_t;
typedef uint16_t error_code_t;
typedef uint32_t serial_number_t;
typedef uint32_t as_number_t;

#define PRINONCE PRIu16


/**
	@return true iff s1 is greater than s2 using serial number arithmetic

	See RFC 1982 for caveats.
*/
bool serial_number_greater(serial_number_t s1, serial_number_t s2);


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
	as_number_t asNumber;
} PACKED_STRUCT IP4PrefixData;

typedef struct _IP6PrefixData {
	uint8_t flags;
	uint8_t prefixLength;
	uint8_t maxLength;
	uint8_t reserved;
	struct in6_addr prefix6;
	as_number_t asNumber;
} PACKED_STRUCT IP6PrefixData;

/*****
 * structure holding the data for an error response
 *****/
typedef struct _ErrorData {
	uint32_t encapsulatedPDULength;
	uint8_t *encapsulatedPDU;
	uint32_t errorTextLength;
	uint8_t *errorText;
} ErrorData;

#define PDU_ERROR_HEADERS_LENGTH (sizeof(uint32_t) + sizeof(uint32_t))

/*****
 * Basic structure of a PDU
 *****/
struct _PDU {
	uint8_t protocolVersion;
	uint8_t pduType;
	union {
		cache_nonce_t cacheNonce;
		uint16_t reserved;
		error_code_t errorCode;
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


#define PDU_GOOD 0 /* valid PDU */
#define PDU_TRUNCATED -1 /* PDU doesn't have errors but is truncated */
#define PDU_WARNING -2 /* PDU has warnings but no errors */
#define PDU_CORRUPT_DATA -3
#define PDU_INTERNAL_ERROR -4
#define PDU_UNSUPPORTED_PROTOCOL_VERSION -5
#define PDU_UNSUPPORTED_PDU_TYPE -6
#define PDU_INVALID_VALUE -7 /* PDU is well-formed but has a field with an invalid value */
#define PDU_IS_ERROR(retval) ((retval) <= PDU_CORRUPT_DATA)
/**
	Attempt to parse as much of buffer as possible into pdu.

	NOTE: pdu may contain pointers into buffer after parsing.
	Use pdu_deepcopy to get a copy that isn't tied to buffer.

	@return one of the above constants
*/
int parse_pdu(uint8_t * buffer, size_t buflen, PDU * pdu);


/**
	Attempt to dump a valid PDU into a buffer.

	@return Number of bytes written, or -1 if there's an error.
*/
ssize_t dump_pdu(uint8_t * buffer, size_t buflen, const PDU * pdu);

void fill_pdu_serial_notify(PDU * pdu, cache_nonce_t nonce, serial_number_t serial);
void fill_pdu_serial_query(PDU * pdu, cache_nonce_t nonce, serial_number_t serial);
void fill_pdu_reset_query(PDU * pdu);
void fill_pdu_cache_response(PDU * pdu, cache_nonce_t nonce);
void fill_pdu_ipv4_prefix(PDU * pdu, uint8_t flags,
	uint8_t prefix_length, uint8_t max_length, const struct in_addr * prefix, as_number_t asn);
void fill_pdu_ipv6_prefix(PDU * pdu, uint8_t flags,
	uint8_t prefix_length, uint8_t max_length, const struct in6_addr * prefix, as_number_t asn);
void fill_pdu_end_of_data(PDU * pdu, cache_nonce_t nonce, serial_number_t serial);
void fill_pdu_cache_reset(PDU * pdu);

/**
	The encapsulated_pdu and error_text parameters are stored in pdu
	without copying. The calling code should handle any necessary copying.

	If encapsulated_pdu or error_text is NULL, its respective length field
	must be 0.
*/
void fill_pdu_error_report(PDU * pdu, error_code_t code,
	uint32_t encapsulated_pdu_length, uint8_t * encapsulated_pdu,
	uint32_t error_text_length, uint8_t * error_text);

/**
	@param pdu a parsed and valid PDU
	@return a deep copy of pdu, or NULL if there isn't enough memory
*/
PDU * pdu_deepcopy(const PDU * pdu);

/** deep free the pdu */
void pdu_free(PDU * pdu);

/** deep free the array of PDUs */
void pdu_free_array(PDU * pdus, size_t num_pdus);

/**
	Print information from the valid pdu onto one line in buffer.
	This is primarily useful for debugging.
*/
#define PDU_SPRINT_BUFSZ 512
void pdu_sprint(const PDU * pdu, char buffer[PDU_SPRINT_BUFSZ]);


#endif
