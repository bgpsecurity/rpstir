/*************************
 * The code for setting up socket connections between the server
 *  and the clients
 *************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <netdb.h>
#include "socket.h"

#define DEFAULT_SERVER_PORT 7455

static int getPort() {
	char *port = getenv ("RPKI_SERVER_PORT");
	return port ? atoi(port) : DEFAULT_SERVER_PORT;
}

#define CHECK_ERR(s, t) \
		 if ((s) == -1) { perror((t)); return -1; }

int getServerSocket() {
	int sock1, sock2;
	struct sockaddr_in sin;

	CHECK_ERR(sock1 = socket(AF_INET, SOCK_STREAM, 0), "socket");
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(getPort());
	CHECK_ERR(bind(sock1, (struct sockaddr *) &sin, sizeof(sin)), "bind");
	CHECK_ERR(listen(sock1, 10), "listen");
	CHECK_ERR(sock2 = accept(sock1, NULL, NULL), "accept");
	return sock2;
}

int getClientSocket(char *hostname) {
	int sock;
	struct hostent *hp;
	struct sockaddr_in sin;

	if ((hp == gethostbyname(hostname)) == 0) {
		printf("Could not find host named %s\n", hostname);
		return -1;
	}
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ((struct in_addr *)(hp->h_addr))->s_addr;
	sin.sin_port = htons(getPort());
	CHECK_ERR(sock = socket(AF_INET, SOCK_STREAM, 0), "socket");
	CHECK_ERR(connect(sock, (struct sockaddr *)&sin, sizeof(sin)), "connect");
	return sock;
}
