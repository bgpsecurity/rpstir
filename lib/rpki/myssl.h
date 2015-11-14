#ifndef LIB_RPKI_MYSSL_H
#define LIB_RPKI_MYSSL_H

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
#include <rpki-object/certificate.h>
#include "rpki-asn1/crlv2.h"


extern int strict_profile_checks;


/*
 * This data structure defines the fields that must be extracted from a
 * certificate in order to insert it into the DB.
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

#define CRL_MAX_SNUM_LTH    20  // maximum length of cert serial number in CRL
#define CRL_MAX_CRLNUM_LTH  20
/*
 * A certificate X509 * must be torn apart into this type of structure. This
 * structure can then be entered into the database.
 */

typedef struct _cert_fields {
    char *fields[CF_NFIELDS];
    void *ipb;
    int ipblen;
    unsigned int dirid;
    unsigned int flags;
} cert_fields;

typedef char *(
    *cf_get)(
    X509 *x,
    int *stap,
    int *x509stap);

typedef void (
    *cfx_get)(
    const X509V3_EXT_METHOD *meth,
    void *exts,
    cert_fields *cf,
    int *stap,
    int *x509stap);

/*
 * For each field in the X509 * that must be extracted, there is a get
 * function. Some fields are mandatory, others are optional. This structure
 * encapsulates the association of field numbers (above), get functions and an
 * indication of whether they are needed or optional. Note that "need"ed here
 * is not the same as a critical extension; a needed extension is one that is
 * required for a database field.
 */

typedef struct _cf_validator {
    cf_get get_func;
    int fieldno;
    int need;
} cf_validator;

/*
 * For each field that is part of the X509 extension, there is a get function.
 * As above, some fields are mandatory, others are optional. This structure
 * encapsulates the association of extension tags, get functions, field
 * numbers and an indication of whether they are needed or optional.
 */

typedef struct _cfx_validator {
    cfx_get get_func;
    int fieldno;
    int tag;
    int need;
    int raw;
} cfx_validator;

extern void freecf(
    cert_fields *);

/**
 * @brief
 *     Convert between a time string in a certificate and a time
 *     string that will be acceptable to the DB.
 *
 * @param[in] in
 *     Time to convert.  The time string can be either UTC or
 *     GENERALIZED.  If @p only_gentime is false, UTC is used for
 *     dates <= 2049 and GENERALIZED is used for dates after >= 2050.
 *     Otherwise, GENERALIZED is use for all dates.
 *
 *     The UTC format takes the form YYMMDDHHMMSST, where each of the
 *     fields is as follows: if YY <= 49 the year is 2000+YY otherwise
 *     it is 1900+YY 1 <= MM <= 12 1 <= DD <= 31 0 <= HH <= 24 0 <= MM
 *     <= 60 0 <= SS <= 60 (seconds field is optional) T, is present
 *     and == Z indicates GMT
 *
 *     The GENERALIZED format takes the form YYYYMMDDHHMMSST, where
 *     the year is given in the full four digit form, and all other
 *     fields are the same.  Note that seconds can be given as either
 *     SS or SS.S.
 *
 *     Both fields can have an optional suffix of the form +HHMM or
 *     -HHMM.
 * @param[out] stap
 *     On success, the value at this "status pointer" is set to 0.  On
 *     failure, it is set to the appropriate error code
 *     (e.g. ERR_SCM_INVALDT).
 * @return
 *     The return value is allocated memory.
 */
extern char *ASNTimeToDBTime(
    char *in,
    int *stap,
    int only_gentime);

/**
 * @brief
 *     converts the local time into GMT in a form recognized by the DB
 */
extern char *LocalTimeToDBTime(
    int *stap);

extern char *UnixTimeToDBTime(
    time_t clck,
    int *stap);

/*
 * This utility function just gets the SKI from an X509 data structure.
 */
extern char *X509_to_ski(
    X509 *x,
    int *stap,
    int *x509stap);

extern char *X509_to_subject(
    X509 *x,
    int *stap,
    int *x509stap);

/*
 * Perform all checks from http://tools.ietf.org/html/rfc6487 that can be done
 * on a single file.
 */
extern int rescert_profile_chk(
    X509 *x,
    struct Certificate *certp,
    int ct);

/**=============================================================================
 * @brief Check CRL conformance to rescert profile, standalone/syntax only
 *
 * @param crlp (struct CertificateRevocationList*)
 * @return 0 on success<br />a negative integer on failure
 *
 * Check CRL conformance with respect to RFCs 5280 and 6487.
  -----------------------------------------------------------------------------*/
extern int crl_profile_chk(
    struct CertificateRevocationList *crlp);

/*
 * This function can operate in two ways.  If "fname" and "fullname" are both
 * given, then it opens a certificate from a file and extracts all the fields
 * from it.  If "xp" points to an already available certificate, then it just
 * manipulates that. This function does not touch the DB at all, it just
 * manipulates the certificate.
 *
 * On success this function returns a pointer to allocated memory containing
 * all the indicated fields (except the "dirid" field) and sets stap to 0, and
 * x509stap to 1.
 *
 * Note carefully that this function does NOT set all the fields in the cf. In
 * particular, it is the responsibility of the caller to set the dirid field.
 * This field requires DB access and are therefore is not part of this
 * function.
 *
 * On failure this function returns NULL and sets stap to a negative error
 * code. If an X509 error occurred, x509stap is set to that error.
 */
extern cert_fields *cert2fields(
    char *fname,
    char *fullname,
    int typ,
    X509 **xp,
    int *stap,
    int *x509stap);

/*
 * This data structure defines the fields that must be extracted from a CRL in
 * order to insert it into the DB.
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
 * A X509_CRL * must be torn apart into this type of structure. This structure
 * can then be entered into the database.
 */

typedef struct _crl_fields {
    char *fields[CRF_NFIELDS];
    void *snlist;
    unsigned int snlen;
    unsigned int dirid;
    unsigned int flags;
} crl_fields;

typedef char *(
    *crf_get)(
    X509_CRL *x,
    int *stap,
    int *crlstap);

typedef void (
    *crfx_get)(
    const X509V3_EXT_METHOD *meth,
    void *exts,
    crl_fields *cf,
    int *stap,
    int *crlstap);

/*
 * For each field in the X509_CRL * that must be extracted, there is a get
 * function. Some fields are mandatory, others are optional. This structure
 * encapsulates the association of field numbers (above), get functions and an
 * indication of whether they are need or optional.
 */

typedef struct _crf_validator {
    crf_get get_func;
    int fieldno;
    int need;
} crf_validator;

/*
 * For each field that is part of the X509_CRL extension, there is a get
 * function. As above, some fields are mandatory, others are optional. This
 * structure encapsulates the association of extension tags, get functions,
 * field numbers and an indication of whether they are needed or optional.
 */

typedef struct _crfx_validator {
    crfx_get get_func;
    int fieldno;
    int tag;
    int need;
} crfx_validator;

extern void freecrf(
    crl_fields *);

/**
 * This function can operate in two ways.  If @p fname and @p fullname
 * are both given, then it opens a CRL from a file and extracts all
 * the fields from it.  If @p xp points to an already available CRL,
 * then it just manipulates that.  This function does not touch the DB
 * at all, it just manipulates the CRL.
 *
 * @note
 *     This function does NOT set all the fields in the returned
 *     ::crl_fields structure.  In particular, it is the
 *     responsibility of the caller to set the crl_fields::dirid
 *     field.  This field requires DB access and is therefore not set
 *     by this function.
 *
 * @param[out] stap
 *     On success the value at this location will be set to 0.  On
 *     failure the value at this location is set to a negative error
 *     code.
 * @param[out] crlstap
 *     On success the value at this location is set to 1.  If an X509
 *     error occured, the value at this location is set to indicate
 *     the particular error.
 * @return
 *     On success this function returns a pointer to allocated memory
 *     containing all the indicated fields (except the
 *     crl_fields::dirid field).  On failure this function returns
 *     NULL.
 */
extern crl_fields *crl2fields(
    char *fname,
    char *fullname,
    int typ,
    X509_CRL **xp,
    int *stap,
    int *crlstap,
    void *goodoidp);

#endif
