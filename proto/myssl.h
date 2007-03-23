#ifndef _MYSSL_H_
#define _MYSSL_H_

/*
  $Id$
*/

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

/*
  This data structure defines the fields that must be extracted from the
  certificate in order to insert it into the DB.
*/

#define CF_FIELD_FILENAME    0
#define CF_FIELD_SUBJECT     1
#define CF_FIELD_ISSUER      2
#define CF_FIELD_SN          3
#define CF_FIELD_FROM        4
#define CF_FIELD_TO          5

#define CF_FIELD_SKI         6
#define CF_FIELD_AKI         7
#define CF_FIELD_SIA         8
#define CF_FIELD_AIA         9
#define CF_FIELD_CRLDP      10

#define CF_NFIELDS          (CF_FIELD_CRLDP+1)


/*
  A certificate X509 * must be torn apart into this type of structure.
  This structure can then be entered into the database.
*/

typedef struct _cert_fields
{
  char *fields[CF_NFIELDS];
  unsigned int dirid;
  unsigned int flags;
} cert_fields;

typedef char *(*cf_get)(X509 *x, int *stap, int *x509stap);

typedef void (*cfx_get)(X509V3_EXT_METHOD *meth, void *exts,
			cert_fields *cf, int *stap, int *x509stap);

/*
  For each field in the X509 * that must be extracted, there is a get
  function. Some fields are mandatory, others are optional. This structure
  encapsulates the association of field numbers (above), get functions and
  an indication of whether they are critical or optional.
*/

typedef struct _cf_validator
{
  cf_get  get_func;
  int     fieldno;
  int     critical;
} cf_validator;

/*
  For each field that is part of the X509 extension, there is a get
  function. As above, some fields are mandatory, others are optional.
  This structure encapsulates the association of extension tags, get
  functions, field numbers and an indication of whether they are critical
  or optional.
*/

typedef struct _cfx_validator
{
  cfx_get  get_func;
  int      fieldno;
  int      tag;
  int      critical;
} cfx_validator ;

extern void  freecf(cert_fields *);

extern char *ASNTimeToDBTime(char *in, int *stap);

extern cert_fields *cert2fields(char *fname, char *fullname, int typ,
				X509 **xp, int *stap, int *x509stap);

#endif
