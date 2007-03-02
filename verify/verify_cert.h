#ifndef __VERIFY_CERT_H
#define __VERIFY_CERT_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "stubs.h"

void handle_error(const char *file, int lineno, const char *msg);
int verify_callback(int ok, X509_STORE_CTX *stor);
int verify_cert(X509 *);

#define int_error(msg)  handle_error(__FILE__, __LINE__, msg);

#endif
