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
  This data structure defines the fields that must be extracted from a
  certificate in order to insert it into the DB.
*/

#define CF_FIELD_FILENAME    0
#define CF_FIELD_SUBJECT     1
#define CF_FIELD_ISSUER      2
#define CF_FIELD_SN          3
#define CF_FIELD_FROM        4
#define CF_FIELD_TO          5
#define CF_FIELD_SIGNATURE   6

#define CF_FIELD_SKI         7
#define CF_FIELD_AKI         8
#define CF_FIELD_SIA         9
#define CF_FIELD_AIA        10
#define CF_FIELD_CRLDP      11

#define CF_NFIELDS          (CF_FIELD_CRLDP+1)


/*
  A certificate X509 * must be torn apart into this type of structure.
  This structure can then be entered into the database.
*/

typedef struct _cert_fields
{
  char *fields[CF_NFIELDS];
  void *ipb;
  int   ipblen;
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
  an indication of whether they are needed or optional. Note that "need"ed
  here is not the same as a critical extension; a needed extension is one
  that is required for a database field.
*/

typedef struct _cf_validator
{
  cf_get  get_func;
  int     fieldno;
  int     need;
} cf_validator;

/*
  For each field that is part of the X509 extension, there is a get
  function. As above, some fields are mandatory, others are optional.
  This structure encapsulates the association of extension tags, get
  functions, field numbers and an indication of whether they are needed
  or optional.
*/

typedef struct _cfx_validator
{
  cfx_get  get_func;
  int      fieldno;
  int      tag;
  int      need;
  int      raw;
} cfx_validator ;

extern void  freecf(cert_fields *);

extern char *ASNTimeToDBTime(char *in, int *stap);
extern char *LocalTimeToDBTime(int *stap);

extern int   rescert_profile_chk(X509 *x, int ct);

extern cert_fields *cert2fields(char *fname, char *fullname, int typ,
				X509 **xp, int *stap, int *x509stap);

/*
  This data structure defines the fields that must be extracted from a
  CRL in order to insert it into the DB.
*/

#define CRF_FIELD_FILENAME    0
#define CRF_FIELD_ISSUER      1
#define CRF_FIELD_LAST        2
#define CRF_FIELD_NEXT        3
#define CRF_FIELD_SIGNATURE   4

#define CRF_FIELD_SN          5
#define CRF_FIELD_AKI         6

#define CRF_NFIELDS         (CRF_FIELD_AKI+1)


/*
  A X509_CRL * must be torn apart into this type of structure.
  This structure can then be entered into the database.
*/

typedef struct _crl_fields
{
  char *fields[CRF_NFIELDS];
  void *snlist;
  unsigned int snlen;
  unsigned int dirid;
  unsigned int flags;
} crl_fields;

typedef char *(*crf_get)(X509_CRL *x, int *stap, int *crlstap);

typedef void (*crfx_get)(X509V3_EXT_METHOD *meth, void *exts,
			 crl_fields *cf, int *stap, int *crlstap);

/*
  For each field in the X509_CRL * that must be extracted, there is a get
  function. Some fields are mandatory, others are optional. This structure
  encapsulates the association of field numbers (above), get functions and
  an indication of whether they are need or optional.
*/

typedef struct _crf_validator
{
  crf_get get_func;
  int     fieldno;
  int     need;
} crf_validator;

/*
  For each field that is part of the X509_CRL extension, there is a get
  function. As above, some fields are mandatory, others are optional.
  This structure encapsulates the association of extension tags, get
  functions, field numbers and an indication of whether they are needed
  or optional.
*/

typedef struct _crfx_validator 
{
  crfx_get get_func;
  int      fieldno;
  int      tag;
  int      need;
} crfx_validator;

extern void  freecrf(crl_fields *);

extern crl_fields *crl2fields(char *fname, char *fullname, int typ,
			       X509_CRL **xp, int *stap, int *crlstap);

#endif
