/*
  $Id: rcli.c 29 2007-03-14 17:28:50Z mreynolds $
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <getopt.h>

#include "scm.h"
#include "scmf.h"
#include "diru.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#include <openssl/bn.h>

X509 *find_certificate(scmcon *conp, char *ski, char *issuer, BIGNUM *sn,
                       int *errp);

/*
  This function looks up a certificate in the database based on one of
  two criteria.  If "ski" is non-NULL it must point to a string containing
  the ASCII representation of a twenty bytes blob in the form
             hex:hex:hex:...:hex
  representing the subject key identifier.  If "ski" is non-NULL, then the
  other two arguments must be NULL.  If "ski" is NULL, then "issuer" is
  a pointer to the distinguished name of the issuer of the certificate,
  and sn is a pointer to an OpenSSL representation of the (bignum)
  serial number.  Both issuer and sn must be non-NULL in this case.

  On success an OpenSSL X509 pointer to the parsed representation of
  the certificate is returned and errp is set to 0. In this case the
  memory must be subsequently freed by a call to X509_free(). On failure
  NULL is returned and errp is set to point to a negative error code.
  Errors can come from the database interface functions, the OpenSSL
  library, or both.
*/
