#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "pdu.h"


#define SEND_PROMPT "> "
#define RECV_PREFIX "< "

#define MAX_PDU_SIZE 65536


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

static int do_send()
{
	// TODO
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
			case PDU_ERROR:
				fprintf(stderr, "received invalid PDU\n");
				return false;
			case PDU_TRUNCATED:
				// more to read
				break;
			default:
				fprintf(stderr, "unexpected return value from parse_pdu()\n");
				return false;
		}

		retval = read(fd, buffer + offset, (size_t)count);
		if (retval < 0)
		{
			perror("read()");
		}
		else if (retval == 0)
		{
			fprintf(stderr, "remote side closed connection in the middle of sending a PDU\n");
			return false;
		}
		else
		{
			count -= retval;
			offset += retval;
		}

		if (offset == PDU_HEADER_LENGTH)
		{
			if (pdu->length > MAX_PDU_SIZE)
			{
				fprintf(stderr, "received PDU that's longer than the maximum size of %d\n", MAX_PDU_SIZE);
				return false;
			}

			count = pdu->length - offset;
		}
	}

	fprintf(stderr, "this should never happen\n");
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
		fprintf(stderr, RECV_PREFIX "%s\n", sprint_buffer);
	}

	return EXIT_SUCCESS;
}

int main(int argc, char ** argv)
{
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
