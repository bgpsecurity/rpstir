#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "logutils.h"

#include "pdu.h"


#define DELIM " \t\n\r"

#define RECV_PREFIX "received "

#define MAX_PDU_SIZE 65536
#define LINEBUF_SIZE 128


static void do_help(const char * argv0)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "    %s [-h | --help]    Print this help text.\n", argv0);
	fprintf(stderr, "    %s send             Run the sending end of a connection.\n", argv0);
	fprintf(stderr, "    %s recv             Run the receiving end of a connection.\n", argv0);
	fprintf(stderr, "\n");
	fprintf(stderr, "    $ %s send | nc <rtr server host> <rtr server port> | %s recv\n", argv0, argv0);
	fprintf(stderr, "\n");
	fprintf(stderr, "On the sending end, you can type the following commands to send PDUs to the server:\n");
	fprintf(stderr, "    serial <nonce> <serial>\n");
	fprintf(stderr, "    reset\n");
	fprintf(stderr, "    error <code>\n");
}


static bool send_pdu(const PDU * pdu, uint8_t buffer[MAX_PDU_SIZE])
{
	ssize_t length = dump_pdu(buffer, MAX_PDU_SIZE, pdu);

	if (length < 0)
	{
		fprintf(stderr, "error in pdu to send");
		return false;
	}

	ssize_t retval;
	ssize_t offset = 0;

	while (offset < length)
	{
		retval = write(STDOUT_FILENO, buffer + offset, (size_t)(length - offset));
		if (retval < 0)
		{
			perror("write()");
			return false;
		}

		offset += retval;
	}

	return true;
}

static int do_send()
{
	char linebuf[LINEBUF_SIZE];
	char * tok;

	PDU pdu;
	uint8_t pdu_buffer[MAX_PDU_SIZE];

	pdu.protocolVersion = RTR_PROTOCOL_VERSION;

	while (true)
	{
		if (fgets(linebuf, LINEBUF_SIZE, stdin) == NULL)
		{
			return EXIT_FAILURE;
		}

		tok = strtok(linebuf, DELIM);

		if (tok == NULL)
		{
			continue;
		}
		else if (strcmp(tok, "serial") == 0)
		{
			tok = strtok(NULL, DELIM);
			if (tok == NULL || sscanf(tok, "%" SCNu16, &pdu.cacheNonce) != 1)
			{
				fprintf(stderr, "usage: serial <nonce> <serial>\n");
				continue;
			}

			tok = strtok(NULL, DELIM);
			if (tok == NULL || sscanf(tok, "%" SCNu32, &pdu.serialNumber) != 1)
			{
				fprintf(stderr, "usage: serial <nonce> <serial>\n");
				continue;
			}

			pdu.pduType = PDU_SERIAL_QUERY;
			pdu.length = PDU_HEADER_LENGTH + sizeof(pdu.serialNumber);

			if (!send_pdu(&pdu, pdu_buffer))
				return EXIT_FAILURE;
		}
		else if (strcmp(tok, "reset") == 0)
		{
			pdu.pduType = PDU_RESET_QUERY;
			pdu.reserved = 0;
			pdu.length = PDU_HEADER_LENGTH;

			if (!send_pdu(&pdu, pdu_buffer))
				return EXIT_FAILURE;
		}
		else if (strcmp(tok, "error") == 0)
		{
			tok = strtok(NULL, DELIM);
			if (tok == NULL || sscanf(tok, "%" SCNu16, &pdu.errorCode) != 1)
			{
				fprintf(stderr, "usage: error <code>\n");
				continue;
			}

			pdu.pduType = PDU_ERROR_REPORT;
			pdu.length = PDU_HEADER_LENGTH + PDU_ERROR_HEADERS_LENGTH;
			pdu.errorData.encapsulatedPDULength = 0;
			pdu.errorData.encapsulatedPDU = NULL;
			pdu.errorData.errorTextLength = 0;
			pdu.errorData.errorText = NULL;

			if (!send_pdu(&pdu, pdu_buffer))
				return EXIT_FAILURE;
		}
		else
		{
			fprintf(stderr, "invalid command: %s\n", tok);
			continue;
		}
	}

	return EXIT_FAILURE;
}


/** read a PDU, return the number of bytes read, or a negative number on error */
static bool read_pdu(int fd, uint8_t buffer[MAX_PDU_SIZE], PDU * pdu)
{
	size_t offset = 0;
	ssize_t count = PDU_HEADER_LENGTH;
	ssize_t retval;

	while (count >= 0)
	{
		switch (parse_pdu(buffer, offset, pdu))
		{
			case PDU_GOOD:
			case PDU_WARNING:
				return true;
			case PDU_TRUNCATED:
				// more to read
				break;
			default:
				log_msg(LOG_NOTICE, "received invalid PDU");
				return false;
		}

		if (offset == PDU_HEADER_LENGTH)
		{
			if (pdu->length > MAX_PDU_SIZE)
			{
				log_msg(LOG_NOTICE, "received %" PRIu32 "-byte PDU (maximum size is %d)", pdu->length, MAX_PDU_SIZE);
				return false;
			}

			count = pdu->length - offset;
		}

		retval = read(fd, buffer + offset, (size_t)count);
		if (retval < 0)
		{
			perror("read()");
		}
		else if (retval == 0)
		{
			if (offset == 0)
			{
				log_msg(LOG_NOTICE, "remote side closed connection");
			}
			else
			{
				log_msg(LOG_NOTICE, "remote side closed connection in the middle of sending a PDU");
			}
			return false;
		}
		else
		{
			count -= retval;
			offset += retval;
		}
	}

	log_msg(LOG_ERR, "this should never happen");
	return false;
}

static int do_recv()
{
	char sprint_buffer[PDU_SPRINT_BUFSZ];
	uint8_t buffer[MAX_PDU_SIZE];
	PDU pdu;

	while (read_pdu(STDIN_FILENO, buffer, &pdu))
	{
		pdu_sprint(&pdu, sprint_buffer);
		log_msg(LOG_INFO, RECV_PREFIX "%s", sprint_buffer);
	}

	return EXIT_SUCCESS;
}

int main(int argc, char ** argv)
{
	if (log_init("rtr-test-client.log", "rtr-test-client", LOG_DEBUG, LOG_DEBUG) != 0)
	{
		perror("log_init()");
		return EXIT_FAILURE;
	}

	if (argc != 2)
	{
		do_help(argv[0]);
		return EXIT_FAILURE;
	}
	else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
	{
		do_help(argv[0]);
		return EXIT_SUCCESS;
	}
	else if (strcmp(argv[1], "send") == 0)
	{
		return do_send();
	}
	else if (strcmp(argv[1], "recv") == 0)
	{
		return do_recv();
	}
	else
	{
		do_help(argv[0]);
		return EXIT_FAILURE;
	}
}
