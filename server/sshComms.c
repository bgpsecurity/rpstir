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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define checkErr(s, str) \
	err = (s); \
	if (err != CRYPT_OK) { printf("Error %s:%d\n", (str), err); return err; }
static int err;  // to be used with checkErr macro


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


int sshOpenClientSession(CRYPT_SESSION *sessionp, char *hostname, int port) {
	checkErr(cryptCreateSession(sessionp, CRYPT_UNUSED,
								CRYPT_SESSION_SSH), "creating session");
	if (setCommonAttribs(*sessionp, port) < 0) return -1;
	checkErr(cryptSetAttributeString(*sessionp, CRYPT_SESSINFO_SERVER_NAME,
									 hostname, strlen(hostname)),
			 "setting server");
	checkErr(cryptSetAttributeString
			 (*sessionp, CRYPT_SESSINFO_USERNAME, "root", 4),
			 "setting username");
	checkErr(cryptSetAttributeString
			 (*sessionp, CRYPT_SESSINFO_PASSWORD, "root", 11),
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
