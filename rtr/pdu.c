#include <assert.h>

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

int parse_pdu(const uint8_t * buffer, size_t buflen, PDU * pdu)
{
	int ret = PDU_GOOD;

	if (buffer == NULL || pdu == NULL)
		return PDU_ERROR;

	#define EXTRACT_FIELD(container_type, container, container_offset, field) \
		do { \
			if (buflen >= container_offset + \
				offsetof(container_type, field) + \
				sizeof(container->field) ) \
			{ \
				container->field = extract_uint( \
					buffer + container_offset + offsetof(container_type, field), \
					sizeof(container->field)); \
			} \
			else \
			{ \
				return PDU_TRUNCATED; \
			} \
		} while (false)

	EXTRACT_FIELD(PDU, pdu, 0, protocolVersion);
	if (pdu->protocolVersion != PROTOCOL_VERSION)
	{
		return PDU_ERROR;
	}

	EXTRACT_FIELD(PDU, pdu, 0, pduType);
	switch (pdu->pduType)
	{
		case PDU_SERIAL_NOTIFY:
		case PDU_SERIAL_QUERY:
		case PDU_CACHE_RESPONSE:
		case PDU_END_OF_DATA
			EXTRACT_FIELD(PDU, pdu, 0, cacheNonce);
			break;
		case PDU_RESET_QUERY:
		case PDU_IPV4_PREFIX:
		case PDU_IPV6_PREFIX:
		case PDU_CACHE_RESET:
			EXTRACT_FIELD(PDU, pdu, 0, reserved);
			if (pdu->reserved != 0)
			{
				ret = PDU_WARNING;
			}
			break;
		case PDU_ERROR_REPORT:
			EXTRACT_FIELD(PDU, pdu, 0, errorCode);
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
			return PDU_ERROR;
	}

	EXTRACT_FIELD(PDU, pdu, 0, length);
	switch (pdu->pduType)
	{
		case PDU_SERIAL_NOTIFY:
		case PDU_SERIAL_QUERY:
		case PDU_END_OF_DATA:
			if (pdu->length != PDU_HEADER_LENGTH + sizeof(pdu->serialNumber))
			{
				return PDU_ERROR;
			}
			EXTRACT_FIELD(PDU, pdu, 0, serialNumber);
			return ret;
		case PDU_RESET_QUERY:
		case PDU_CACHE_RESPONSE:
		case PDU_CACHE_RESET:
			if (pdu->length != PDU_HEADER_LENGTH)
			{
				return PDU_ERROR;
			}
			return ret;
		case PDU_IPV4_PREFIX:
		case PDU_IPV6_PREFIX:
			return PDU_ERROR; // TODO: these obviously aren't always errors
		case PDU_ERROR_REPORT:
			if (pdu->length < PDU_HEADER_LENGTH + PDU_ERROR_HEADERS_LENGTH)
			{
				return PDU_ERROR;
			}
			return PDU_ERROR; // TODO: these obviously aren't always errors
		default:
			// this really shouldn't happen...
			return PDU_ERROR;
	}

	#undef EXTRACT_FIELD
}
