#ifndef __STUBS_H
#define __STUBS_H

#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pem.h>

int is_trust_anchor(X509 *, int);
X509 *getParentCert(X509 *, int);

#endif
