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

#include "sshComms.h"
#include "pdu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>


#define checkErr(s, str) \
	err = (s); \
	if (err != CRYPT_OK) { printf("Error %s:%d\n", (str), err); return err; }
static int err;  // to be used with checkErr macro

#define checkerr2(s, args...) \
	if ((s) < 0) { fprintf(stderr, args); return -1; }


static pid_t childpid = 0;   // remember this so that can close it later


int initSSHProcess(char *host) {
	int writepipe[2] = {-1,-1}, readpipe[2] = {-1,-1};
	checkerr2(pipe(readpipe) < 0  ||  pipe(writepipe) < 0,
			  "Cannot create pipes\n");
	checkerr2(childpid = fork(), "Cannot fork child\n");
	if ( childpid == 0 ) { /* in the child */
		close(writepipe[1]);
		close(readpipe[0]);
		dup2(writepipe[0], STDIN_FILENO);  close(writepipe[0]);
		dup2(readpipe[1], STDOUT_FILENO);  close(readpipe[1]);
		char cmd[256];
		snprintf(cmd, sizeof(cmd), "ssh -s %s rpki-rtr\n", host);
		system(cmd);
		fprintf(stderr, "Child process unexpected exit\n");
		exit(-1);
	}
	else { /* in the parent */
		close(readpipe[1]);
		close(writepipe[0]);
		setPipes(readpipe[0], writepipe[1]);
	}
	return 0;
}

int killSSHProcess() {
	int pid = childpid;
	childpid = 0;
	if (pid == 0) return -1;
	closePipes();
	return kill(pid, SIGKILL);
}


int initSSH() {
	checkErr(cryptInit(), "initializing cryptlib");
	return 0;
}


static int setCommonAttribs(CRYPT_SESSION sess, int port) {
	CRYPT_CONTEXT privateKey;

	cryptSetAttribute(sess, CRYPT_OPTION_NET_READTIMEOUT, 2);
	cryptSetAttribute(sess, CRYPT_OPTION_NET_WRITETIMEOUT, 2);
	cryptSetAttribute(sess, CRYPT_OPTION_NET_CONNECTTIMEOUT, 900000000);

	// eventually, read the key from file rather than generating it
	checkErr(cryptCreateContext(&privateKey, CRYPT_UNUSED, CRYPT_ALGO_RSA),
			 "creating context");
	checkErr(cryptSetAttributeString(privateKey, CRYPT_CTXINFO_LABEL,
									 "Private key", 11 ), "setting label");
	checkErr(cryptGenerateKey(privateKey), "generating key");
	checkErr(cryptSetAttribute(sess, CRYPT_SESSINFO_PRIVATEKEY,
							   privateKey), "setting private key");

	checkErr(cryptSetAttribute(sess, CRYPT_SESSINFO_SERVER_PORT, port),
			 "setting port");
	return 0;
}


int sshOpenServerSession(CRYPT_SESSION *sessionp, int port) {
	checkErr(cryptCreateSession(sessionp, CRYPT_UNUSED,
								CRYPT_SESSION_SSH_SERVER), "creating session");
	if (setCommonAttribs(*sessionp, port) < 0) return -1;

	// eventually, do real authentication
	cryptSetAttribute(*sessionp, CRYPT_SESSINFO_AUTHRESPONSE, 1);
	checkErr(cryptSetAttribute(*sessionp, CRYPT_SESSINFO_ACTIVE, 1),
			 "doing SSH handshake");
	return 0;
}


int sshOpenClientSession(CRYPT_SESSION *sessionp, char *hostname,
						 int port, char *username, char *password) {
	checkErr(cryptCreateSession(sessionp, CRYPT_UNUSED,
								CRYPT_SESSION_SSH), "creating session");
	if (setCommonAttribs(*sessionp, port) < 0) return -1;
	checkErr(cryptSetAttributeString(*sessionp, CRYPT_SESSINFO_SERVER_NAME,
									 hostname, strlen(hostname)),
			 "setting server");
	checkErr(cryptSetAttributeString
			 (*sessionp, CRYPT_SESSINFO_USERNAME, username, strlen(username)),
			 "setting username");
	checkErr(cryptSetAttributeString
			 (*sessionp, CRYPT_SESSINFO_PASSWORD, password, strlen(password)),
			 "setting password");
	checkErr(cryptSetAttribute(*sessionp, CRYPT_SESSINFO_SSH_CHANNEL,
							   CRYPT_UNUSED), "seetting channel");
	checkErr(cryptSetAttributeString(*sessionp,
									 CRYPT_SESSINFO_SSH_CHANNEL_TYPE,
									 "subsystem", 9), "setting chan type");
	checkErr(cryptSetAttributeString(*sessionp,
									 CRYPT_SESSINFO_SSH_CHANNEL_ARG1,
									 "rpki-rtr", 8), "setting arg1");
	checkErr(cryptSetAttribute(*sessionp, CRYPT_SESSINFO_ACTIVE, 1),
			 "doing SSH handshake");
	return 0;
}


int sshCloseSession(CRYPT_SESSION session) {
	return cryptDestroySession(session);
}


int sshCollect(CRYPT_SESSION session, void *data, int numBytes) {
	int num;
	checkErr(cryptPushData(session, data, numBytes, &num), "writing data");
	return num;
}


int sshSendCollected(CRYPT_SESSION session) {
	checkErr(cryptFlushData(session), "flushing data");
	return 0;
}


int sshReceive(CRYPT_SESSION session, void *buffer, int maxBytes) {
	int num;
	checkErr(cryptPopData(session, buffer, maxBytes, &num), "reading data");
	return num;
}


/**************************
 * some code snippets that could be useful eventually
 * write a keyset and create a cert

static int create_rsa_key( )
{
	int err;
	// Create a context for RSA
	CRYPT_CONTEXT privKeyContext;
	int  keyLen = 128; // 1024 bit
	checkCrypt(cryptCreateContext(&privKeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA), "creating privkey context");
	// Set a label for the key
	checkCrypt(cryptSetAttributeString(privKeyContext, CRYPT_CTXINFO_LABEL,
									   "RSA_KEY", 7 ), "privkey label");
	// Set key length
	checkCrypt(cryptSetAttribute(privKeyContext, CRYPT_CTXINFO_KEYSIZE, keyLen), "setting key len");
	// Generate a key
	checkCrypt(cryptGenerateKey(privKeyContext), "generating privkey");
	// Open a Keysey file
	CRYPT_KEYSET keySet;
	checkCrypt(cryptKeysetOpen(&keySet, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							   "keyset.p15", CRYPT_KEYOPT_CREATE), "keyset open");
	// Store the private key
	checkCrypt(cryptAddPrivateKey(keySet, privKeyContext, "boza" ), "storing key");
	checkCrypt(cryptKeysetClose( keySet ), "closing keyset");
	return 0;
}

	checkCrypt(cryptCreateCert( &cryptCertificate, cryptUser,
								CRYPT_CERTTYPE_CERTIFICATE), "creating cert");
	checkCrypt(cryptSetAttribute( cryptCertificate, CRYPT_CERTINFO_XYZZY, 1),
			   "setting xyzzy");
	checkCrypt(cryptSetAttribute( cryptCertificate,
								  CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
								  cryptContext ), "seting public");
	checkCrypt(cryptSetAttributeString( cryptCertificate,
										CRYPT_CERTINFO_COMMONNAME,
										"Dave Smith", 10 ), "seting name");
	checkCrypt(cryptSignCert( cryptCertificate, cryptContext ), "signing");
	checkCrypt(cryptSetAttribute(cryptSession, CRYPT_SESSINFO_CACERTIFICATE,
								 cryptContext), "setting ca cert");

*************************/
