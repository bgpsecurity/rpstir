#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <ctype.h>

#include "pdu.h"

// switch to uintmax_t instead of uint_fast32_t? 32 should be enough for this protocol version
static uint_fast32_t extract_uint(const uint8_t * buffer, size_t length)
{
	assert(buffer != NULL);
	assert(length <= sizeof(uint_fast32_t));

	uint_fast32_t ret = 0;

	size_t i;

	for (i = 0; i < length; ++i)
		ret |= buffer[i] << (8 * (length - 1 - i));

	return ret;
}

int parse_pdu(uint8_t * buffer, size_t buflen, PDU * pdu)
{
	int ret = PDU_GOOD;
	size_t offset = 0;

	if (buffer == NULL || pdu == NULL)
		return PDU_INTERNAL_ERROR;

	#define EXTRACT_FIELD(field) \
		do { \
			if (buflen >= offset + sizeof(field)) \
			{ \
				field = extract_uint(buffer + offset, sizeof(field)); \
				offset += sizeof(field); \
			} \
			else \
			{ \
				return PDU_TRUNCATED; \
			} \
		} while (false)

	#define EXTRACT_BIN_FIELD(field) \
		do { \
			if (buflen >= offset + sizeof(field)) \
			{ \
				memcpy(&field, buffer + offset, sizeof(field)); \
				offset += sizeof(field); \
			} \
			else \
			{ \
				return PDU_TRUNCATED; \
			} \
		} while (false)

	EXTRACT_FIELD(pdu->protocolVersion);
	if (pdu->protocolVersion != RTR_PROTOCOL_VERSION)
	{
		return PDU_UNSUPPORTED_PROTOCOL_VERSION;
	}

	EXTRACT_FIELD(pdu->pduType);
	switch (pdu->pduType)
	{
		case PDU_SERIAL_NOTIFY:
		case PDU_SERIAL_QUERY:
		case PDU_CACHE_RESPONSE:
		case PDU_END_OF_DATA:
			EXTRACT_FIELD(pdu->cacheNonce);
			break;
		case PDU_RESET_QUERY:
		case PDU_IPV4_PREFIX:
		case PDU_IPV6_PREFIX:
		case PDU_CACHE_RESET:
			EXTRACT_FIELD(pdu->reserved);
			if (pdu->reserved != 0)
			{
				ret = PDU_WARNING;
			}
			break;
		case PDU_ERROR_REPORT:
			EXTRACT_FIELD(pdu->errorCode);
			if (pdu->errorCode != ERR_CORRUPT_DATA &&
				pdu->errorCode != ERR_INTERNAL_ERROR &&
				pdu->errorCode != ERR_NO_DATA &&
				pdu->errorCode != ERR_INVALID_REQUEST &&
				pdu->errorCode != ERR_UNSUPPORTED_VERSION &&
				pdu->errorCode != ERR_UNSUPPORTED_TYPE &&
				pdu->errorCode != ERR_UNKNOWN_WITHDRAW &&
				pdu->errorCode != ERR_DUPLICATE_ANNOUNCE)
			{
				ret = PDU_WARNING;
			}
			break;
		default:
			return PDU_UNSUPPORTED_PDU_TYPE;
	}

	EXTRACT_FIELD(pdu->length);
	switch (pdu->pduType)
	{
		case PDU_SERIAL_NOTIFY:
		case PDU_SERIAL_QUERY:
		case PDU_END_OF_DATA:
			if (pdu->length != PDU_HEADER_LENGTH + sizeof(pdu->serialNumber))
			{
				return PDU_CORRUPT_DATA;
			}
			EXTRACT_FIELD(pdu->serialNumber);
			return ret;
		case PDU_RESET_QUERY:
		case PDU_CACHE_RESPONSE:
		case PDU_CACHE_RESET:
			if (pdu->length != PDU_HEADER_LENGTH)
			{
				return PDU_CORRUPT_DATA;
			}
			return ret;
		case PDU_IPV4_PREFIX:
			if (pdu->length != PDU_HEADER_LENGTH + sizeof(IP4PrefixData))
			{
				return PDU_CORRUPT_DATA;
			}

			EXTRACT_FIELD(pdu->ip4PrefixData.flags);
			if (pdu->ip4PrefixData.flags & FLAGS_RESERVED)
			{
				ret = PDU_WARNING;
			}

			EXTRACT_FIELD(pdu->ip4PrefixData.prefixLength);
			if (pdu->ip4PrefixData.prefixLength > 32)
			{
				return PDU_INVALID_VALUE;
			}

			EXTRACT_FIELD(pdu->ip4PrefixData.maxLength);
			if (pdu->ip4PrefixData.maxLength > 32)
			{
				return PDU_INVALID_VALUE;
			}

			if (pdu->ip4PrefixData.prefixLength > pdu->ip4PrefixData.maxLength)
			{
				ret = PDU_WARNING;
			}

			EXTRACT_FIELD(pdu->ip4PrefixData.reserved);
			if (pdu->ip4PrefixData.reserved != 0)
			{
				ret = PDU_WARNING;
			}

			EXTRACT_BIN_FIELD(pdu->ip4PrefixData.prefix4);

			EXTRACT_FIELD(pdu->ip4PrefixData.asNumber);

			return ret;
		case PDU_IPV6_PREFIX:
			if (pdu->length != PDU_HEADER_LENGTH + sizeof(IP6PrefixData))
			{
				return PDU_CORRUPT_DATA;
			}

			EXTRACT_FIELD(pdu->ip6PrefixData.flags);
			if (pdu->ip6PrefixData.flags & FLAGS_RESERVED)
			{
				ret = PDU_WARNING;
			}

			EXTRACT_FIELD(pdu->ip6PrefixData.prefixLength);
			if (pdu->ip6PrefixData.prefixLength > 128)
			{
				return PDU_INVALID_VALUE;
			}

			EXTRACT_FIELD(pdu->ip6PrefixData.maxLength);
			if (pdu->ip6PrefixData.maxLength > 128)
			{
				return PDU_INVALID_VALUE;
			}

			if (pdu->ip6PrefixData.prefixLength > pdu->ip6PrefixData.maxLength)
			{
				ret = PDU_WARNING;
			}

			EXTRACT_FIELD(pdu->ip6PrefixData.reserved);
			if (pdu->ip6PrefixData.reserved != 0)
			{
				ret = PDU_WARNING;
			}

			EXTRACT_BIN_FIELD(pdu->ip6PrefixData.prefix6);

			EXTRACT_FIELD(pdu->ip6PrefixData.asNumber);

			return ret;
		case PDU_ERROR_REPORT:
			if (pdu->length < PDU_HEADER_LENGTH + PDU_ERROR_HEADERS_LENGTH)
			{
				return PDU_CORRUPT_DATA;
			}

			EXTRACT_FIELD(pdu->errorData.encapsulatedPDULength);
			if (pdu->length < PDU_HEADER_LENGTH + PDU_ERROR_HEADERS_LENGTH + pdu->errorData.encapsulatedPDULength)
			{
				return PDU_CORRUPT_DATA;
			}

			if (buflen < offset + pdu->errorData.encapsulatedPDULength)
			{
				return PDU_TRUNCATED;
			}
			pdu->errorData.encapsulatedPDU = buffer + offset;
			offset += pdu->errorData.encapsulatedPDULength;

			EXTRACT_FIELD(pdu->errorData.errorTextLength);
			if (pdu->length != PDU_HEADER_LENGTH + PDU_ERROR_HEADERS_LENGTH + pdu->errorData.encapsulatedPDULength + pdu->errorData.errorTextLength)
			{
				return PDU_CORRUPT_DATA;
			}

			if (buflen < offset + pdu->errorData.errorTextLength)
			{
				return PDU_TRUNCATED;
			}
			pdu->errorData.errorText = buffer + offset;
			offset += pdu->errorData.errorTextLength;

			return ret;
		default:
			// this really shouldn't happen...
			return PDU_INTERNAL_ERROR;
	}

	#undef EXTRACT_BIN_FIELD
	#undef EXTRACT_FIELD
}


ssize_t dump_pdu(uint8_t * buffer, size_t buflen, const PDU * pdu)
{
	if (buffer == NULL)
		return -1;

	if (pdu == NULL)
		return 0;

	size_t offset = 0;

	#define INCR_OFFSET(num_bytes) \
		do { \
			if (offset + (num_bytes) > buflen) \
			{ \
				return -1; \
			} \
			offset += (num_bytes); \
		} while (false)

	INCR_OFFSET(2); // protocolVersion and pduType
	memcpy(buffer, (void *)pdu, 2);

	INCR_OFFSET(2); // cacheNonce, reserved, and errorCode
	*(uint16_t *)(buffer + offset - 2) = htons(pdu->cacheNonce);

	INCR_OFFSET(4); // length
	*(uint32_t *)(buffer + offset - 4) = htonl(pdu->length);

	assert(offset == PDU_HEADER_LENGTH);

	if (pdu->pduType == PDU_ERROR_REPORT)
	{
		INCR_OFFSET(4);
		*(uint32_t *)(buffer + offset - 4) = htonl(pdu->errorData.encapsulatedPDULength);

		INCR_OFFSET(pdu->errorData.encapsulatedPDULength);
		memcpy(buffer + offset - pdu->errorData.encapsulatedPDULength,
			pdu->errorData.encapsulatedPDU,
			pdu->errorData.encapsulatedPDULength);

		INCR_OFFSET(4);
		*(uint32_t *)(buffer + offset - 4) = htonl(pdu->errorData.errorTextLength);

		INCR_OFFSET(pdu->errorData.errorTextLength);
		if (pdu->errorData.errorTextLength > 0)
			memcpy(buffer + offset - pdu->errorData.errorTextLength, pdu->errorData.errorText, pdu->errorData.errorTextLength);
	}
	else
	{
		INCR_OFFSET(pdu->length - PDU_HEADER_LENGTH);
		memcpy(buffer + PDU_HEADER_LENGTH, (void *)pdu + PDU_HEADER_LENGTH, pdu->length - PDU_HEADER_LENGTH);

		if (pdu->pduType == PDU_IPV4_PREFIX || pdu->pduType == PDU_IPV6_PREFIX)
		{
			// IP4PrefixData and IP6PrefixData are both in the correct order except for the as_number_t at the end
			*(uint32_t *)(buffer + offset - 4) = htonl(*(uint32_t *)(buffer + offset - 4));
		}
		else if (pdu->pduType == PDU_SERIAL_NOTIFY ||
			pdu->pduType == PDU_SERIAL_QUERY ||
			pdu->pduType == PDU_END_OF_DATA)
		{
			// These require fixing the order of the serial number
			*(uint32_t *)(buffer + PDU_HEADER_LENGTH) = htonl(*(uint32_t *)(buffer + PDU_HEADER_LENGTH));
		}
	}

	#undef INCR_OFFSET

	return (ssize_t)offset;
}


static void _fill_pdu_common(PDU * pdu, uint8_t type, uint32_t length)
{
	pdu->protocolVersion = RTR_PROTOCOL_VERSION;
	pdu->pduType = type;
	pdu->length = length;
}

static void _fill_pdu_with_serial_number(
	PDU * pdu,
	uint8_t type,
	uint16_t nonce_or_zero, // nonce if the type has one, zero if the type doesn't
	serial_number_t serial
) {
	_fill_pdu_common(pdu, type, PDU_HEADER_LENGTH + sizeof(pdu->serialNumber));
	pdu->cacheNonce = nonce_or_zero;
	pdu->serialNumber = serial;
}

static void _fill_pdu_header_only(
	PDU * pdu,
	uint8_t type,
	uint16_t nonce_or_zero // nonce if the type has one, zero if the type doesn't
) {
	_fill_pdu_common(pdu, type, PDU_HEADER_LENGTH);
	pdu->cacheNonce = nonce_or_zero;
}

void fill_pdu_serial_notify(PDU * pdu, cache_nonce_t nonce, serial_number_t serial)
{
	_fill_pdu_with_serial_number(pdu, PDU_SERIAL_NOTIFY, nonce, serial);
}

void fill_pdu_serial_query(PDU * pdu, cache_nonce_t nonce, serial_number_t serial)
{
	_fill_pdu_with_serial_number(pdu, PDU_SERIAL_QUERY, nonce, serial);
}

void fill_pdu_reset_query(PDU * pdu)
{
	_fill_pdu_header_only(pdu, PDU_RESET_QUERY, 0);
}

void fill_pdu_cache_response(PDU * pdu, cache_nonce_t nonce)
{
	_fill_pdu_header_only(pdu, PDU_CACHE_RESPONSE, nonce);
}

void fill_pdu_ipv4_prefix(PDU * pdu, uint8_t flags,
	uint8_t prefix_length, uint8_t max_length, const struct in_addr * prefix, as_number_t asn)
{
	_fill_pdu_common(pdu, PDU_IPV4_PREFIX, PDU_HEADER_LENGTH + sizeof(pdu->ip4PrefixData));
	pdu->reserved = 0;
	pdu->ip4PrefixData.flags = flags;
	pdu->ip4PrefixData.prefixLength = prefix_length;
	pdu->ip4PrefixData.maxLength = max_length;
	pdu->ip4PrefixData.reserved = 0;
	pdu->ip4PrefixData.prefix4 = *prefix;
	pdu->ip4PrefixData.asNumber = asn;
}

void fill_pdu_ipv6_prefix(PDU * pdu, uint8_t flags,
	uint8_t prefix_length, uint8_t max_length, const struct in6_addr * prefix, as_number_t asn)
{
	_fill_pdu_common(pdu, PDU_IPV6_PREFIX, PDU_HEADER_LENGTH + sizeof(pdu->ip6PrefixData));
	pdu->reserved = 0;
	pdu->ip6PrefixData.flags = flags;
	pdu->ip6PrefixData.prefixLength = prefix_length;
	pdu->ip6PrefixData.maxLength = max_length;
	pdu->ip6PrefixData.reserved = 0;
	pdu->ip6PrefixData.prefix6 = *prefix;
	pdu->ip6PrefixData.asNumber = asn;
}

void fill_pdu_end_of_data(PDU * pdu, cache_nonce_t nonce, serial_number_t serial)
{
	_fill_pdu_with_serial_number(pdu, PDU_END_OF_DATA, nonce, serial);
}

void fill_pdu_cache_reset(PDU * pdu)
{
	_fill_pdu_header_only(pdu, PDU_CACHE_RESET, 0);
}


PDU * pdu_deepcopy(const PDU * pdu)
{
	PDU * ret = malloc(sizeof(PDU));
	if (ret == NULL)
		return NULL;

	memcpy(ret, pdu, sizeof(PDU));

	if (ret->pduType == PDU_ERROR_REPORT)
	{
		if (ret->errorData.encapsulatedPDU != NULL)
		{
			ret->errorData.encapsulatedPDU = malloc(ret->errorData.encapsulatedPDULength);
			if (ret->errorData.encapsulatedPDU == NULL)
			{
				free((void *)ret);
				return NULL;
			}

			memcpy(ret->errorData.encapsulatedPDU, pdu->errorData.encapsulatedPDU, ret->errorData.encapsulatedPDULength);
		}

		if (ret->errorData.errorText != NULL)
		{
			ret->errorData.errorText = malloc(ret->errorData.errorTextLength);
			if (ret->errorData.errorText == NULL)
			{
				free((void *)ret->errorData.encapsulatedPDU);
				free((void *)ret);
				return NULL;
			}

			memcpy(ret->errorData.errorText, pdu->errorData.errorText, ret->errorData.errorTextLength);
		}
	}

	return ret;
}


static void _pdu_free_internal(PDU * pdu)
{
	if (pdu == NULL)
		return;

	if (pdu->pduType == PDU_ERROR_REPORT)
	{
		free((void *)pdu->errorData.encapsulatedPDU);
		free((void *)pdu->errorData.errorText);
	}
}

void pdu_free(PDU * pdu)
{
	if (pdu == NULL)
		return;

	_pdu_free_internal(pdu);

	free((void *)pdu);
}

void pdu_free_array(PDU * pdus, size_t num_pdus)
{
	if (pdus == NULL)
		return;

	size_t i;

	for (i = 0; i < num_pdus; ++i)
		_pdu_free_internal(&pdus[i]);

	free((void *)pdus);
}


void pdu_sprint(const PDU * pdu, char buffer[PDU_SPRINT_BUFSZ])
{
	bool truncated = false;
	int offset = 0;
	uint32_t i;

	#define SNPRINTF(format, ...) \
		do { \
			if (offset < PDU_SPRINT_BUFSZ) \
			{ \
				offset += snprintf(buffer + offset, PDU_SPRINT_BUFSZ - offset, format, ## __VA_ARGS__); \
			} \
			\
			if (offset >= PDU_SPRINT_BUFSZ) \
			{ \
				truncated = true; \
				goto buffer_full; \
			} \
		} while (false)

	#define SNPRINTF_FLAGS(flags) \
		do { \
			SNPRINTF("0x%" PRIx8 " [", (flags)); \
			if ((flags) & FLAG_WITHDRAW_ANNOUNCE) \
			{ \
				SNPRINTF("ANNOUNCE"); \
			} \
			else \
			{ \
				SNPRINTF("WITHDRAW"); \
			} \
			if ((flags) & FLAGS_RESERVED) \
			{ \
				SNPRINTF(", <RESERVED>"); \
			} \
			SNPRINTF("]"); \
		} while (false)

	#define SNPRINTF_IP4(ip) \
		do { \
			if (offset + INET_ADDRSTRLEN < PDU_SPRINT_BUFSZ) \
			{ \
				if (inet_ntop(AF_INET, &(ip), buffer + offset, PDU_SPRINT_BUFSZ - offset) == NULL) \
				{ \
					SNPRINTF("(ERROR)"); \
				} \
				else \
				{ \
					while (buffer[offset] != '\0') \
						++offset; \
				} \
			} \
			else \
			{ \
				SNPRINTF("..."); \
			} \
		} while (false)

	#define SNPRINTF_IP6(ip) \
		do { \
			if (offset + INET6_ADDRSTRLEN < PDU_SPRINT_BUFSZ) \
			{ \
				if (inet_ntop(AF_INET6, &(ip), buffer + offset, PDU_SPRINT_BUFSZ - offset) == NULL) \
				{ \
					SNPRINTF("(ERROR)"); \
				} \
				else \
				{ \
					while (buffer[offset] != '\0') \
						++offset; \
				} \
			} \
			else \
			{ \
				SNPRINTF("..."); \
			} \
		} while (false)

	if (pdu == NULL)
	{
		SNPRINTF("(NULL)");
		return;
	}

	SNPRINTF("version %" PRIu8, pdu->protocolVersion);

	switch (pdu->pduType)
	{
		case PDU_SERIAL_NOTIFY:
			SNPRINTF(" Serial Notify");
			break;
		case PDU_SERIAL_QUERY:
			SNPRINTF(" Serial Query");
			break;
		case PDU_RESET_QUERY:
			SNPRINTF(" Reset Query");
			break;
		case PDU_CACHE_RESPONSE:
			SNPRINTF(" Cache Response");
			break;
		case PDU_IPV4_PREFIX:
			SNPRINTF(" IPv4 Prefix");
			break;
		case PDU_IPV6_PREFIX:
			SNPRINTF(" IPv6 Prefix");
			break;
		case PDU_END_OF_DATA:
			SNPRINTF(" End of Data");
			break;
		case PDU_CACHE_RESET:
			SNPRINTF(" Cache Reset");
			break;
		case PDU_ERROR_REPORT:
			SNPRINTF(" Error Report");
			break;
		default:
			SNPRINTF(" unknown type (%" PRIu8 ")", pdu->pduType);
			break;
	}

	switch (pdu->pduType)
	{
		case PDU_SERIAL_NOTIFY:
		case PDU_SERIAL_QUERY:
		case PDU_CACHE_RESPONSE:
		case PDU_END_OF_DATA:
			SNPRINTF(", cache nonce = %" PRIu16, pdu->cacheNonce);
			break;
		case PDU_RESET_QUERY:
		case PDU_IPV4_PREFIX:
		case PDU_IPV6_PREFIX:
		case PDU_CACHE_RESET:
			// don't bother printing the reserved field
			break;
		case PDU_ERROR_REPORT:
			switch (pdu->errorCode)
			{
				case ERR_CORRUPT_DATA:
					SNPRINTF(" (Corrupt Data)");
					break;
				case ERR_INTERNAL_ERROR:
					SNPRINTF(" (Internal Error)");
					break;
				case ERR_NO_DATA:
					SNPRINTF(" (No Data)");
					break;
				case ERR_INVALID_REQUEST:
					SNPRINTF(" (Invalid Request)");
					break;
				case ERR_UNSUPPORTED_VERSION:
					SNPRINTF(" (Unsupported Version)");
					break;
				case ERR_UNSUPPORTED_TYPE:
					SNPRINTF(" (Unsupported Type)");
					break;
				case ERR_UNKNOWN_WITHDRAW:
					SNPRINTF(" (Unknown Withdraw)");
					break;
				case ERR_DUPLICATE_ANNOUNCE:
					SNPRINTF(" (Duplicate Announce)");
					break;
				default:
					SNPRINTF(" (unknown error code %" PRIu16 ")", pdu->errorCode);
					break;
			}
			break;
		default:
			break;
	}

	SNPRINTF(", length = %" PRIu32, pdu->length);

	switch (pdu->pduType)
	{
		case PDU_SERIAL_NOTIFY:
		case PDU_SERIAL_QUERY:
		case PDU_END_OF_DATA:
			SNPRINTF(", serial number = %" PRIu32, pdu->serialNumber);
			break;
		case PDU_RESET_QUERY:
		case PDU_CACHE_RESPONSE:
		case PDU_CACHE_RESET:
			break;
		case PDU_IPV4_PREFIX:
			SNPRINTF(", flags = ");
			SNPRINTF_FLAGS(pdu->ip4PrefixData.flags);
			SNPRINTF(", prefix length = %" PRIu8, pdu->ip4PrefixData.prefixLength);
			SNPRINTF(", max length = %" PRIu8, pdu->ip4PrefixData.maxLength);
			SNPRINTF(", prefix = ");
			SNPRINTF_IP4(pdu->ip4PrefixData.prefix4);
			SNPRINTF(", AS number = %" PRIu32, pdu->ip4PrefixData.asNumber);
			break;
		case PDU_IPV6_PREFIX:
			SNPRINTF(", flags = ");
			SNPRINTF_FLAGS(pdu->ip6PrefixData.flags);
			SNPRINTF(", prefix length = %" PRIu8, pdu->ip6PrefixData.prefixLength);
			SNPRINTF(", max length = %" PRIu8, pdu->ip6PrefixData.maxLength);
			SNPRINTF(", prefix = ");
			SNPRINTF_IP6(pdu->ip6PrefixData.prefix6);
			SNPRINTF(", AS number = %" PRIu32, pdu->ip6PrefixData.asNumber);
			break;
		case PDU_ERROR_REPORT:
			SNPRINTF(", encapsulated PDU length = %" PRIu32, pdu->errorData.encapsulatedPDULength);
			SNPRINTF(", error text = [%" PRIu32 "] \"", pdu->errorData.errorTextLength);
			for (i = 0; i < pdu->errorData.errorTextLength; ++i)
			{
				if (pdu->errorData.errorText[i] == '"' ||
					pdu->errorData.errorText[i] == '\\')
				{
					SNPRINTF("\\%c", pdu->errorData.errorText[i]);
				}
				else if (!isprint(pdu->errorData.errorText[i]) ||
					(isspace(pdu->errorData.errorText[i]) &&
						pdu->errorData.errorText[i] != ' '))
				{
					SNPRINTF("\\x%02" PRIx8, pdu->errorData.errorText[i]);
				}
				else
				{
					SNPRINTF("%c", pdu->errorData.errorText[i]);
				}
			}
			SNPRINTF("\"");
			break;
		default:
			break;
	}

	#undef SNPRINTF_IP6
	#undef SNPRINTF_IP4
	#undef SNPRINTF_FLAGS
	#undef SNPRINTF

	#define TRUNCATED_STR " ..."
	#define TRUNCATED_STRLEN 4

buffer_full:
	if (truncated)
	{
		if (offset + TRUNCATED_STRLEN + 1 < PDU_SPRINT_BUFSZ)
		{
			strncpy(buffer + offset, TRUNCATED_STR, TRUNCATED_STRLEN + 1);
		}
		else
		{
			strncpy(buffer + PDU_SPRINT_BUFSZ - TRUNCATED_STRLEN - 1, TRUNCATED_STR, TRUNCATED_STRLEN + 1);
		}
	}

	#undef TRUNCATED_STRLEN
	#undef TRUNCATED_STR
}
