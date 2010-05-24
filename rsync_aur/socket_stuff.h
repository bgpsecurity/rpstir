#ifndef __SOCKET_STUFF_H
#define __SOCKET_STUFF_H

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
 * Contributor(s):  Peiter "Mudge" Zatko
 *
 * ***** END LICENSE BLOCK ***** */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#ifdef __NetBSD__
#include <netinet/in.h>
#endif
#ifdef __FreeBSD__
#include <netinet/in.h>
#endif

#define LOCAL 0
#define TCP 1
#define UDP 2

/*
  $Id$
*/

struct write_port {
  int out_desc;
  struct sockaddr_in server_addr;
  struct hostent *host;
  int to_length;
  int protocol;
};

int tcpsocket(struct write_port *, int);
int udpsocket(struct write_port *, int);
int outputMsg(struct write_port *, char *, unsigned int);


#endif
