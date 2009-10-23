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
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
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

/******
 * Initialize the SSH library, must call this once before anything else
 * Returns 0 on success, negative number on error
 ******/
int initSSH(void);

/******
 * Waits for a connection from a client and opens a SSH session
 * Returns 0 on success, negative number on error
 ******/
int sshOpenServerSession(CRYPT_SESSION *sessionp);

/******
 * Waits for a connection to a server and opens a SSH session
 * Argument: hostname - host name of the server
 * Returns 0 on success, negative number on error
 ******/
int sshOpenClientSession(CRYPT_SESSION *sessionp, char *hostname);

/**********
 * close an ssh session
 * Returns 0 on success, negative number on error
 ******/
int sshCloseSession(CRYPT_SESSION session);

/******
 * Accumulate data to send across the ssh connection
 * Returns number of bytes accepted on success, negative number on error
 ******/
int sshCollect(CRYPT_SESSION session, void *data, int numBytes);

/******
 * Send all accumulated data across the ssh connection
 * Returns number of bytes sent on success, negative number on error
 ******/
int sshSendCollected(CRYPT_SESSION session);

/******
 * Read data from the ssh connection
 * Returns number of bytes read on success, negative number on error
 ******/
int sshReceive(CRYPT_SESSION session, void *buffer, int maxBytes);

#endif
