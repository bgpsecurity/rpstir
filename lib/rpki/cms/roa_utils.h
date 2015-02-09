#ifndef LIB_RPKI_CMS_ROA_UTILS_H
#define LIB_RPKI_CMS_ROA_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <util/cryptlib_compat.h>

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
#include <rpki-asn1/cms.h>

#include "rpki/err.h"

// #define FALSE 0
// #define TRUE 1

#define cFALSE 0
#define cTRUE  1

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))

#ifndef min
#define min(a,b) ((a)<(b)?(a):(b))
#endif                          /* min */

// #define ROA_VALID 0
// #define ROA_INVALID 1

// JFG - Reinsert this definition here if ranges are reinstated in asn
// #define IP_RANGES_ALLOWED

extern int strict_profile_checks_cms;

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

struct badfile {
    char *fname;
    int err;
};

/*
 * This function reads the file at "fname" and parses it.  Presuming the file
 * represents a ROA in syntactically correct openssl conf file format, the
 * function will allocate space for and return a ROA structure at the location
 * pointed to by "rp".
 *
 * On success this function returns 0; on failure it returns a negative error
 * code.
 *
 * The non-NULL return from this function is allocated memory that must be
 * freed by a call to roaFree().
 */
int roaFromConfig(
    char *fname,
    int doval,
    struct CMS *rp);

/*
 * NOT REQUIRED to be implemented
 *
 * This function is the inverse of the previous function.  The ROA defined by
 * "r" is written to the file named "fname" using the standard conf file
 * format (paired KEY= VALUE statements)
 *
 * On success this function returns 0; on failure it returns a negative error
 * code.
 */
int roaToConfig(
    struct CMS *r,
    char *fname);

/*
 * This is a more generalized function for similar purposes.  It reads in a
 * ROA from a file and potentially perform validation. "fname" is the name of
 * the file containing the putative ROA. If "fmt" is 0 this function attempts
 * to intuit the file format based on the first CR or LF delimited line in the
 * file and also the filename; if "fmt" is non-zero then it is an OpenSSL enum
 * value specifying the file format (binary DER or PEM encoded DER).
 *
 * If "doval" is any nonzero value then the ROA will also be semantically
 * validated using all steps that do not require access to the database; if
 * "doval" is 0 only ASN.1 syntatic validation will be performed.
 *
 * On success a ROA data structure, as defined in roa.h, is returned and errp
 * is set to 0.  On failure NULL is returned and errp is set to a negative
 * error code.
 *
 * The non-NULL return from this function is allocated memory that must be
 * freed by a call to roaFree().
 */
int roaFromFile(
    char *fname,
    int fmt,
    int doval,
    struct CMS *rp);

/*
 * This function is the inverse of the previous function.  The ROA defined by
 * "r" is written to the file named "fname" using the format "fmt".  If "fmt"
 * is 0 the output form is the default (PEM encoded DER).
 *
 * On success this function returns 0; on failure it returns a negative error
 * code.
 */
int roaToFile(
    struct CMS *r,
    char *fname,
    int fmt);

/*
 * This function is used to create BGP filter tables from a ROA and its
 * certificate.  The contents of "r" and "cert" are examined, the AS-number
 * and IP-address associations are extracted, and the result is appended to
 * the file "fp".  Note that this function may produce an non-negative number
 * of lines of output (including zero).
 *
 * It is assumed that the ROA "r" has already been validated.
 *
 * On success this function returns 0; on failure it returns a negative error
 * code.
 */
int roaGenerateFilter(
    struct CMS *r,
    uchar *cert,
    FILE *fp,
    char *str,
    int strLen);

/*
 * Similar to above but allocates space for result as needed
 */
int roaGenerateFilter2(
    struct CMS *r,
    char **str);

/**
 * @brief Represent a prefix from a ROA.
 */
struct roa_prefix
{
    /**
     * @brief Length of #prefix, either 4 for IPv4 or 16 for IPv6.
     */
    uint8_t prefix_family_length;

    uint8_t prefix[16];

    uint8_t prefix_length;

    uint8_t prefix_max_length;
};

/**
 * @brief Extract the prefixes from a ROA.
 *
 * @param[in] r The ROA.
 * @param[out] prefixes On success, *prefixes will be set to point to
 *     an array of roa prefixes. This value must be free()ed by the
 *     caller. On failure, *prefixes will be set to NULL.
 * @return On success, the number of prefixes. On failure, a negative
 *     number.
 */
ssize_t roaGetPrefixes(
    struct CMS *r,
    struct roa_prefix * * prefixes);

/*
 * This utility function extracts the SKI from a ROA and formats it in the
 * canonical ASCII format hex:hex:...:hex, suitable for use in DB lookups.  On
 * failure this function returns NULL.
 *
 * Note that this function returns a pointer to allocated memory that must be
 * free()d by the caller.
 */
unsigned char *roaSKI(
    struct CMS *r);

/*
 * This utility function extracts the binary signature from the ROA and
 * returns a pointer to it. It additional sets the (binary) length of the data
 * pointed to in "lenp". It is the responsibility of the caller to convert the
 * binary data into an alternate form, if desired. On failure this function
 * returns NULL.
 */
unsigned char *roaSignature(
    struct CMS *r,
    int *lenp);

/*
 * This utility function extracts the AS# from a ROA and returns it. Only
 * call this after roaValidate() passes.
 */
uint32_t roaAS_ID(
    struct CMS *r);

/*
 * This function performs all validations steps on a ROA that do not require
 * database access.  On success it returns 0; on failure, it returns a
 * negative error code.
 *
 * Make sure that the ROA meets the provisions outlined in RFC 6482.
 * Checks are limited to those that can be done using the standalone
 * ROA.
 */
int roaValidate(
    struct CMS *r);

/**=========================================================================
 * @brief Check conformance to manifest profile
 *
 * This function performs all validation steps on a manifest that do
 * not require database access.
 *
 * @param manp (struct ROA *)
 * @param stalep Return parameter to store whether or not the manifest is
 *               stale. It's value is only guaranteed to be initialized if
 *               this function returns 0.
 * @return 0 on success<br />a negative integer on failure
 *
 * Check manifest conformance with respect to the manifest profile
 *   (draft-ietf-sidr-rpki-manifests).
 *
 * 4. Manifest definition
 *
 * A manifest is an RPKI signed object, as specified in
 * [ID.sidr-signed-object].  The RPKI signed object template requires
 * specification of the following data elements in the context of the
 * manifest structure.
 *
 * 4.1 eContentType
 *
 * The eContentType for a Manifest is defined as id-ct-rpkiManifest, and
 * has the numerical value of 1.2.840.113549.1.9.16.1.26.
 *
 *   id-smime OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
 *                                    rsadsi(113549) pkcs(1) pkcs9(9) 16 }
 *
 *   id-ct OBJECT IDENTIFIER ::= { id-smime 1 }
 *
 *   id-ct-rpkiManifest OBJECT IDENTIFIER ::= { id-ct 26 }
 *
 * 4.2 eContent
 *
 *   The content of a manifest is defined as follows:
 *
 * Manifest ::= SEQUENCE {
 *   version     [0] INTEGER DEFAULT 0,
 *   manifestNumber  INTEGER (0..MAX),
 *   thisUpdate      GeneralizedTime,
 *   nextUpdate      GeneralizedTime,
 *   fileHashAlg     OBJECT IDENTIFIER,
 *   fileList        SEQUENCE SIZE (0..MAX) OF FileAndHash
 *   }
 *
 * FileAndHash ::=     SEQUENCE {
 *   file            IA5String,
 *   hash            BIT STRING
 *   }
 *
 * 4.2.1 Manifest
 *
 *   The manifestNumber, thisUpdate, and nextUpdate fields are modeled
 *   after the corresponding fields in X.509 CRLs (see [RFC5280]).
 *   Analogous to CRLs, a manifest is nominally current until the time
 *   specified in nextUpdate or until a manifest is issued with a greater
 *   manifest number, whichever comes first.
 *
 *   If a "one-time-use" EE certificate is employed to verify a manifest,
 *   the EE certificate MUST have an validity period that coincides with
 *   the interval from thisUpdate to nextUpdate, to prevent needless
 *   growth of the CA's CRL.
 *
 *   If a "sequential-use" EE certificate is employed to verify a
 *   manifest, the EE certificate's validity period needs to be no shorter
 *   than the nextUpdate time of the current manifest.  The extended
 *   validity time raises the possibility of a substitution attack using a
 *   stale manifest, as described in Section 6.4.
 */
int manifestValidate(
    struct CMS *r,
    int *stalep);

/*
 * This function performs all validation steps on a ghostbusters
 * record that do not require database access.  On success it returns
 * 0; on failure, it returns a negative error code.
 */
int ghostbustersValidate(
    struct CMS *cms);

/*
 * This function performs all validations steps on a ROA that require an X509
 * certificate to have been fetched from the database. It returns 0 on success
 * and a negative error code on failure. It is assumed that this function is
 * called as follows:
 *
 *     scm *scmp; // previously opened DB schema
 *     scmcon *conp; // previously opened DB connection
 *     X509 *cert;
 *     uchar *blob;
 *     char *ski;
 *     char *fn;
 *     int valid = -1;
 *     int sta;
 *
 *     sta = roaValidate(r);
 *     if (sta == 0) {
 *         ski = (char *)roaSKI(r);
 *         if (ski != NULL) {
 *             cert = roa_parent(scmp, conp, ski, &fn, &sta);
 *             if (cert != NULL && sta == 0) {
 *                 blob = read cert from file (fn);
 *                 valid = roaValidate2(r, blob);
 *             }
 *         }
 *     }
 */
extern int roaValidate2(
    struct CMS *r);

/*
 * If the hash is given as "inhash", check to see that the hash inside the
 * FileAndHash struct is the same. If the hash is not given in "inhash" then
 * compute the hash, check it against the hash in FileAndHash, and then store
 * the hash (if the comparison succeeded) in "inhash". "inhashlen" is the
 * number of bytes actually used in "inhash" (which is a binary array, not a
 * string), and "inhashtotlen" is the total space available in that array.
 *
 * On success this function returns the length, in bytes, of the hash. On
 * failure it returns a negative error code.
 */
int check_fileAndHash(
    struct FileAndHash *fahp,
    int fd,
    uchar *inhash,
    int inhashlen,
    int inhashtotlen);

/*
 * This function performs all validations steps on a ROA that require an X509
 * certificate to have been fetched from the database. It returns 0 on success
 * and a negative error code on failure.  Any files with bad hashes are listed
 * in badfilespp as an array of char*, the last of which is null. The caller
 * is responsible for freeing each char* and then the array.
 */
int manifestValidate2(
    struct CMS *r,
    char *dir,
    struct badfile ***badfilesppp);

void free_badfiles(
    struct badfile **badfilespp);

/*
 * This function frees all memory allocated when "r" was created. It is
 * permissible for "r" to be NULL, in which case nothing happens. If "r" is
 * non-NULL, however, it must point to a syntatically valid ROA structure
 * (which need not have been semantically validated, however).
 */
void roaFree(
    struct CMS *r);

/*
 * This function checks the signature on a ROA.
 */
int check_sig(
    struct CMS *rp,
    struct Certificate *certp);

/*
 * This function decodes a PEM encoded file whose contents are stored in
 * "bufIn" of length "inSize" and produces the corresponding DER (raw ASN.1)
 * data in "bufOut" of length "outSize". Note that it allocates memory to do
 * this, which the caller must free.
 */
int decode_b64(
    unsigned char *bufIn,
    int inSize,
    unsigned char **bufOut,
    int *outSize,
    char *armor);

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(A) ((void)A)
#endif

#endif
