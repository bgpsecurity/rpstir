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

/*************************
 * The code for establishing SSH connections between the server
 *  and the clients
 *************************/

#ifndef _SSHCOMMS_H
#define _SSHCOMMS_H

#include <cryptlib.h>


/* if running server standalone, default port number it listens on */
#define DEFAULT_STANDALONE_PORT 7455
#define DEFAULT_SSH_PORT 22

#define TIMEOUT_TEXT "Socket timed out\n"

/*****
 * Set up child process, set up pipes to have the parent able to
 *   write to stdin of child and read from stdout, and have the child
 *   run ssh while the parent returns after setting these pipes as
 *   those used by the PDU reading and writing routines
 * Returns -1 on failure, 0 on success
 * Only use this if client and not in standalone mode
 *****/
int initSSHProcess(char *host, int port, char *user);

/*****
 * Kill the child process most recently opened by initSSHProcess
 * Returns negative error code on failure, 0 on success
 *****/
int killSSHProcess(void);

/******
 * Initialize the SSH library, must call this once before anything else
 * Returns 0 on success, negative number on error
 * Only call this if in standalone mode
 ******/
int initSSH(void);

/******
 * Waits for a connection from a client and opens a SSH session
 * Argument: port - port number to listen on
 * Returns 0 on success, negative number on error
 * Only call this if in standalone mode
 ******/
int sshOpenServerSession(CRYPT_SESSION *sessionp, int port);

/******
 * Waits for a connection to a server and opens a SSH session
 * Argument: hostname, port - host name and port of the server
 * Returns 0 on success, negative number on error
 * Only call this if in standalone mode
 ******/
int sshOpenClientSession(CRYPT_SESSION *sessionp, char *hostname,
						 int port, char *username, char *password);

/**********
 * close an ssh session
 * Returns 0 on success, negative number on error
 * Only call this if in standalone mode
 ******/
int sshCloseSession(CRYPT_SESSION session);

/******
 * Accumulate data to send across the ssh connection
 * Returns number of bytes accepted on success, negative number on error
 * Only call this if in standalone mode
 ******/
int sshCollect(CRYPT_SESSION session, void *data, int numBytes);

/******
 * Send all accumulated data across the ssh connection
 * Returns number of bytes sent on success, negative number on error
 * Only call this if in standalone mode
 ******/
int sshSendCollected(CRYPT_SESSION session);

/******
 * Read data from the ssh connection
 * Returns number of bytes read on success, negative number on error
 * Only call this if in standalone mode
 ******/
int sshReceive(CRYPT_SESSION session, void *buffer, int maxBytes);

#endif
