#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>

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
		case PDU_END_OF_DATA:
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


ssize_t dump_pdu(uint8_t * buffer, size_t buflen, const PDU * pdu)
{
	if (buffer == NULL)
		return -1;

	if (pdu == NULL)
		return 0;

	ssize_t retval;

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

		retval = dump_pdu(buffer + offset, buflen - offset, pdu->errorData.encapsulatedPDU);
		if (retval < 0)
			return retval;
		else
			offset += retval;

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
	}

	#undef INCR_OFFSET

	return (ssize_t)offset;
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

			if (ret->errorData.encapsulatedPDU->pduType == PDU_ERROR_REPORT)
			{
				// This isn't a valid PDU, so it shouldn't have been passed to this function.
				// Allowing error report PDUs to contain error report PDUs could allow infinite loops.
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
