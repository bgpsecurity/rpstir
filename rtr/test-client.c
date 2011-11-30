#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "logutils.h"

#include "pdu.h"


#define DELIM " \t\n\r"

#define RECV_PREFIX "received "

#define MAX_PDU_SIZE 65536
#define LINEBUF_SIZE 128

// all the arguments a command (for sending) can take
enum command_argument {
	ARG_NONCE,
	ARG_SERIAL,
	ARG_PREFIX_FLAGS,
	ARG_PREFIX_LENGTH,
	ARG_PREFIX_MAX_LENGTH,
	ARG_IPv4,
	ARG_IPv6,
	ARG_AS_NUMBER,
	ARG_ERROR_CODE,
	ARG_END // special argument to indicate the end of the argument list
};

static const char * arg_name(enum command_argument arg)
{
	switch (arg)
	{
		case ARG_NONCE: return "nonce";
		case ARG_SERIAL: return "serial";
		case ARG_PREFIX_FLAGS: return "prefix flags";
		case ARG_PREFIX_LENGTH: return "prefix length";
		case ARG_PREFIX_MAX_LENGTH: return "prefix max length";
		case ARG_IPv4: return "IPv4 address";
		case ARG_IPv6: return "IPv6 address";
		case ARG_AS_NUMBER: return "AS number";
		case ARG_ERROR_CODE: return "error code";
		default: return NULL;
	}
}


struct command;

static void cmd_serial_notify(const struct command * command, char const * const * args);
static void cmd_serial_query(const struct command * command, char const * const * args);
static void cmd_reset_query(const struct command * command, char const * const * args);
static void cmd_cache_response(const struct command * command, char const * const * args);
static void cmd_ipv4_prefix(const struct command * command, char const * const * args);
static void cmd_ipv6_prefix(const struct command * command, char const * const * args);
static void cmd_end_of_data(const struct command * command, char const * const * args);
static void cmd_cache_reset(const struct command * command, char const * const * args);
static void cmd_error_report(const struct command * command, char const * const * args);

#define MAX_NUM_ARGS 10
struct command {
	char * name;
	void (*function)(const struct command * command, char const * const * args);
	enum command_argument args[MAX_NUM_ARGS];
};

static const struct command commands[] = {
	{"serial_notify", cmd_serial_notify, {ARG_NONCE, ARG_SERIAL, ARG_END}},
	{"serial_query", cmd_serial_query, {ARG_NONCE, ARG_SERIAL, ARG_END}},
	{"reset_query", cmd_reset_query, {ARG_END}},
	{"cache_response", cmd_cache_response, {ARG_NONCE, ARG_END}},
	{"ipv4_prefix", cmd_ipv4_prefix, {ARG_PREFIX_FLAGS, ARG_PREFIX_LENGTH, ARG_PREFIX_MAX_LENGTH, ARG_IPv4, ARG_AS_NUMBER, ARG_END}},
	{"ipv6_prefix", cmd_ipv6_prefix, {ARG_PREFIX_FLAGS, ARG_PREFIX_LENGTH, ARG_PREFIX_MAX_LENGTH, ARG_IPv6, ARG_AS_NUMBER, ARG_END}},
	{"end_of_data", cmd_end_of_data, {ARG_NONCE, ARG_SERIAL, ARG_END}},
	{"cache_reset", cmd_cache_reset, {ARG_END}},
	{"error_report", cmd_error_report, {ARG_ERROR_CODE, ARG_END}},
	{NULL, NULL, {ARG_END}}
};

static void command_print_usage_signature(
	FILE * out,
	const struct command * command,
	const char * print_before,
	const char * print_after)
{
	size_t i;

	fprintf(out, "%s%s", print_before, command->name);
	for (i = 0; command->args[i] != ARG_END; ++i)
	{
		fprintf(out, " <%s>", arg_name(command->args[i]));
	}
	fprintf(out, "%s", print_after);
}


static void do_help(const char * argv0)
{
	size_t i;

	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "    %s [-h | --help]    Print this help text.\n", argv0);
	fprintf(stderr, "    %s send             Run the sending end of a connection.\n", argv0);
	fprintf(stderr, "    %s recv             Run the receiving end of a connection.\n", argv0);
	fprintf(stderr, "\n");
	fprintf(stderr, "    $ %s send | nc <rtr server host> <rtr server port> | %s recv\n", argv0, argv0);
	fprintf(stderr, "\n");
	fprintf(stderr, "On the sending end, you can type the following commands to send PDUs to the server:\n");
	for (i = 0; commands[i].name != NULL; ++i)
	{
		command_print_usage_signature(stderr, &commands[i], "    ", "\n");
	}
}

static inline bool _command_get_arg_sscanf(
	const char * arg_string,
	const char * format,
	void * arg_value)
{
	return sscanf(arg_string, format, arg_value) == 1;
}

static bool command_get_arg(
	const struct command * command,
	char const * const * args,
	size_t arg_index,
	void * arg_value)
{
	char const * const arg_string = args[arg_index];
	bool ret;

	if (arg_string == NULL)
	{
		ret = false;
		goto done;
	}

	switch(command->args[arg_index])
	{
		case ARG_NONCE:
			ret = _command_get_arg_sscanf(arg_string, "%" SCNu16, arg_value);
			goto done;

		case ARG_SERIAL:
			ret = _command_get_arg_sscanf(arg_string, "%" SCNu32, arg_value);
			goto done;

		case ARG_PREFIX_FLAGS:
			ret = _command_get_arg_sscanf(arg_string, "%" SCNu8, arg_value);
			goto done;

		case ARG_PREFIX_LENGTH:
			ret = _command_get_arg_sscanf(arg_string, "%" SCNu8, arg_value);
			goto done;

		case ARG_PREFIX_MAX_LENGTH:
			ret = _command_get_arg_sscanf(arg_string, "%" SCNu8, arg_value);
			goto done;

		case ARG_IPv4:
			ret = inet_pton(AF_INET, arg_string, arg_value) == 1;
			goto done;

		case ARG_IPv6:
			ret = inet_pton(AF_INET6, arg_string, arg_value) == 1;
			goto done;

		case ARG_AS_NUMBER:
			ret = _command_get_arg_sscanf(arg_string, "%" SCNu32, arg_value);
			goto done;

		case ARG_ERROR_CODE:
			ret = _command_get_arg_sscanf(arg_string, "%" SCNu16, arg_value);
			goto done;

		default:
			ret = false;
			goto done;
	}

done:
	if (!ret)
	{
		command_print_usage_signature(stderr, command, "usage: ", "\n");
	}

	return ret;
}


static void send_pdu(const PDU * pdu)
{
	uint8_t buffer[MAX_PDU_SIZE];
	ssize_t length = dump_pdu(buffer, MAX_PDU_SIZE, pdu);

	if (length < 0)
	{
		fprintf(stderr, "error in pdu to send");
		exit(EXIT_FAILURE);
	}

	ssize_t retval;
	ssize_t offset = 0;

	while (offset < length)
	{
		retval = write(STDOUT_FILENO, buffer + offset, (size_t)(length - offset));
		if (retval < 0)
		{
			perror("write()");
			exit(EXIT_FAILURE);
		}

		offset += retval;
	}
}

static void cmd_serial_notify(const struct command * command, char const * const * args)
{
	cache_nonce_t nonce;
	serial_number_t serial;

	if (!command_get_arg(command, args, 0, &nonce)) return;
	if (!command_get_arg(command, args, 1, &serial)) return;

	PDU pdu;
	fill_pdu_serial_notify(&pdu, nonce, serial);

	send_pdu(&pdu);
}

static void cmd_serial_query(const struct command * command, char const * const * args)
{
	cache_nonce_t nonce;
	serial_number_t serial;

	if (!command_get_arg(command, args, 0, &nonce)) return;
	if (!command_get_arg(command, args, 1, &serial)) return;

	PDU pdu;
	fill_pdu_serial_query(&pdu, nonce, serial);

	send_pdu(&pdu);
}

static void cmd_reset_query(const struct command * command, char const * const * args)
{
	(void)command;
	(void)args;

	PDU pdu;
	fill_pdu_reset_query(&pdu);

	send_pdu(&pdu);
}

static void cmd_cache_response(const struct command * command, char const * const * args)
{
	cache_nonce_t nonce;

	if (!command_get_arg(command, args, 0, &nonce)) return;

	PDU pdu;
	fill_pdu_cache_response(&pdu, nonce);

	send_pdu(&pdu);
}

static void cmd_ipv4_prefix(const struct command * command, char const * const * args)
{
	uint8_t flags;
	uint8_t prefix_length;
	uint8_t max_length;
	struct in_addr prefix;
	as_number_t asn;

	if (!command_get_arg(command, args, 0, &flags)) return;
	if (!command_get_arg(command, args, 1, &prefix_length)) return;
	if (!command_get_arg(command, args, 2, &max_length)) return;
	if (!command_get_arg(command, args, 3, &prefix)) return;
	if (!command_get_arg(command, args, 4, &asn)) return;

	PDU pdu;
	fill_pdu_ipv4_prefix(&pdu, flags, prefix_length, max_length, &prefix, asn);

	send_pdu(&pdu);
}

static void cmd_ipv6_prefix(const struct command * command, char const * const * args)
{
	uint8_t flags;
	uint8_t prefix_length;
	uint8_t max_length;
	struct in6_addr prefix;
	as_number_t asn;

	if (!command_get_arg(command, args, 0, &flags)) return;
	if (!command_get_arg(command, args, 1, &prefix_length)) return;
	if (!command_get_arg(command, args, 2, &max_length)) return;
	if (!command_get_arg(command, args, 3, &prefix)) return;
	if (!command_get_arg(command, args, 4, &asn)) return;

	PDU pdu;
	fill_pdu_ipv6_prefix(&pdu, flags, prefix_length, max_length, &prefix, asn);

	send_pdu(&pdu);
}

static void cmd_end_of_data(const struct command * command, char const * const * args)
{
	cache_nonce_t nonce;
	serial_number_t serial;

	if (!command_get_arg(command, args, 0, &nonce)) return;
	if (!command_get_arg(command, args, 1, &serial)) return;

	PDU pdu;
	fill_pdu_end_of_data(&pdu, nonce, serial);

	send_pdu(&pdu);
}

static void cmd_cache_reset(const struct command * command, char const * const * args)
{
	(void)command;
	(void)args;

	PDU pdu;
	fill_pdu_cache_reset(&pdu);

	send_pdu(&pdu);
}

static void cmd_error_report(const struct command * command, char const * const * args)
{
	PDU pdu;

	pdu.protocolVersion = RTR_PROTOCOL_VERSION;
	if (!command_get_arg(command, args, 0, &pdu.errorCode)) return;
	pdu.pduType = PDU_ERROR_REPORT;
	pdu.length = PDU_HEADER_LENGTH + PDU_ERROR_HEADERS_LENGTH;
	pdu.errorData.encapsulatedPDULength = 0;
	pdu.errorData.encapsulatedPDU = NULL;
	pdu.errorData.errorTextLength = 0;
	pdu.errorData.errorText = NULL;

	send_pdu(&pdu);
}

static int do_send()
{
	char linebuf[LINEBUF_SIZE];
	char * tok;
	char const * command_args[MAX_NUM_ARGS];
	size_t i, j;

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

		for (i = 0; commands[i].name != NULL; ++i)
		{
			if (strcmp(tok, commands[i].name) == 0)
			{
				for (j = 0; commands[i].args[j] != ARG_END; ++j)
				{
					command_args[j] = strtok(NULL, DELIM);
				}

				commands[i].function(&commands[i], command_args);
				break;
			}
		}
		if (commands[i].name != NULL)
		{
			continue;
		}

		fprintf(stderr, "invalid command: %s\n", tok);
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
