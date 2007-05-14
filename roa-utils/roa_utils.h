/*
  $Id$
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>

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

// Generated from the asn definition
#include <roa.h>

#include "err.h"

//#define FALSE 0
//#define TRUE 1

#define cFALSE 0
#define cTRUE  1

//#define ROA_VALID 0
//#define ROA_INVALID 1

// JFG - Reinsert this definition here if ranges are reinstated in asn
//#define IP_RANGES_ALLOWED

enum asnFileFormat {
  FMT_CONF = 0,
  FMT_PEM,
  FMT_DER
};

enum ianaAfis {
  NOAFI = 0,
  IPV4,
  IPV6
};

int roaFromConfig(char *fname, int doval, struct ROA** rp);

/*
  This function reads the file at "fname" and parses it.  Presuming the file
  represents a ROA in syntactically correct openssl conf file format,
  the function will allocate space for and return a ROA structure at the
  location pointed to by "rp".  

  On success this function returns 0; on failure it returns a negative
  error code.

  The non-NULL return from this function is allocated memory that
  must be freed by a call to roaFree().
*/

int roaToConfig(struct ROA* r, char *fname);

/*
  NOT REQUIRED to be implemented

  This function is the inverse of the previous function.  The ROA
  defined by "r" is written to the file named "fname" using the standard
  conf file format (paired KEY= VALUE statements)

  On success this function returns 0; on failure it returns a negative
  error code.
*/

int roaFromFile(char *fname, int fmt, int doval, struct ROA **rp);

/*
  This is a more generalized function for similar purposes.  It
  reads in a ROA from a file and potentially perform validation.
  "fname" is the name of the file containing the putative ROA.
  If "fmt" is 0 this function attempts to intuit the file format
  based on the first CR or LF delimited line in the file and also
  the filename; if "fmt" is non-zero then it is an OpenSSL enum value
  specifying the file format (binary DER or PEM encoded DER).
  
  If "doval" is any nonzero value then the ROA will also be semantically
  validated using all steps that do not require access to the database;
  if "doval" is 0 only ASN.1 syntatic validation will be performed.

  On success a ROA data structure, as defined in roa.h, is returned
  and errp is set to 0.  On failure NULL is returned and errp is
  set to a negative error code.

  The non-NULL return from this function is allocated memory that
  must be freed by a call to roaFree().
*/

int roaToFile(struct ROA *r, char *fname, int fmt);

/*
  This function is the inverse of the previous function.  The ROA
  defined by "r" is written to the file named "fname" using the format
  "fmt".  If "fmt" is 0 the output form is the default (PEM encoded DER).

  On success this function returns 0; on failure it returns a negative
  error code.
*/

int roaGenerateFilter(struct ROA *r, X509 *cert, FILE *fp);

/*
  This function is used to create BGP filter tables from a ROA and its
  certificate.  The contents of "r" and "cert" are examined, the AS-number
  and IP-address associations are extracted, and the result is appended
  to the file "fp".  Note that this function may produce an non-negative
  number of lines of output (including zero).

  On success this function returns 0; on failure it returns a negative
  error code.
*/

unsigned char *roaSKI(struct ROA *r);

/*
  This utility function extracts the SKI from a ROA and formats it in
  the canonical ASCII format hex:hex:...:hex, suitable for use in DB
  lookups.  On failure this function returns NULL.

  Note that this function returns a pointer to allocated memory that
  must be free()d by the caller.
*/

int roaValidate(struct ROA *r);

/*
  This function performs all validations steps on a ROA that do not
  require database access.  On success it returns 0; on failure, it
  returns a negative error code.
*/

int roaValidate2(struct ROA *r, X509 *x);

/*
  This function performs all validations steps on a ROA that require
  an X509 certificate to have been fetched from the database. It returns 0
  on success and a negative error code on failure. It is assumed that this
  function is called as follows:

      scmcon *conp; // previously opened DB connection
      X509   *cert;
      char   *ski;
      int     valid = -1;
      int     sta;

      sta = roaValidate(r);
      if ( sta == 0 ) {
        ski = roaSKI(r);
	if ( ski != NULL ) {
	  cert = find_certificate(conp, ski, NULL, NULL, &sta);
	  if ( cert != NULL && sta == 0 ) {
            valid = roaValidate2(r, cert);
          }
        }
      }
*/

void roaFree(struct ROA *r);

/*
  This function frees all memory allocated when "r" was created. It
  is permissible for "r" to be NULL, in which case nothing happens.
  If "r" is non-NULL, however, it must point to a syntatically valid
  ROA structure (which need not have been semantically validated, however).
*/
