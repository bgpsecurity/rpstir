#ifndef LIB_RPKI_ERR_H
#define LIB_RPKI_ERR_H

#include "util/logging.h"

#include <stdio.h>
#include <stdlib.h>

/*
 * Error codes
 */

/**
 * @brief
 *     helper macro to avoid typing out the list of error codes
 *     multiple times
 */
#define ERROR_CODES(f)                                                  \
    f(ERR_SCM_NOERR, "No error") /* this entry must be first */         \
    f(ERR_SCM_UNSPECIFIED, "Unspecified error")                         \
    f(ERR_SCM_COFILE, "Cannot open file")                               \
    f(ERR_SCM_NOMEM, "Out of memory")                                   \
    f(ERR_SCM_INVALARG, "Invalid argument")                             \
    f(ERR_SCM_SQL, "SQL error")                                         \
    f(ERR_SCM_INVALCOL, "Invalid column")                               \
    f(ERR_SCM_NULLCOL, "Null column")                                   \
    f(ERR_SCM_NOSUCHTAB, "No such table")                               \
    f(ERR_SCM_NODATA, "No data")                                        \
    f(ERR_SCM_NULLVALP, "Null value")                                   \
    f(ERR_SCM_INVALSZ, "Invalid size")                                  \
    f(ERR_SCM_ISLINK, "Link skipped")                                   \
    f(ERR_SCM_BADFILE, "Bad filename or file not found")                \
    f(ERR_SCM_INVALFN, "Inconsistent filename")                         \
    f(ERR_SCM_NOTADIR, "Not a directory")                               \
    f(ERR_SCM_INTERNAL, "Internal error")                               \
    f(ERR_SCM_X509, "X509 error")                                       \
    f(ERR_SCM_BADCERT, "Error reading cert")                            \
    f(ERR_SCM_NOSUBJECT, "Missing subject field")                       \
    f(ERR_SCM_NOISSUER, "Missing issuer field")                         \
    f(ERR_SCM_NOSN, "Missing serial number")                            \
    f(ERR_SCM_BIGNUMERR, "Bignum error")                                \
    f(ERR_SCM_NONB4, "Missing start date")                              \
    f(ERR_SCM_NONAF, "Missing end date")                                \
    f(ERR_SCM_INVALDT, "Invalid date/time")                             \
    f(ERR_SCM_BADEXT, "Extension error")                                \
    f(ERR_SCM_INVALEXT, "Invalid extension")                            \
    f(ERR_SCM_XPROFILE, "Profile violation")                            \
    f(ERR_SCM_MISSEXT, "Missing extension")                             \
    f(ERR_SCM_NOTSS, "Not self-signed")                                 \
    f(ERR_SCM_NOTVALID, "Certificate validation error")                 \
    f(ERR_SCM_CERTCTX, "Certificate context error")                     \
    f(ERR_SCM_X509STACK, "X509 stack error")                            \
    f(ERR_SCM_STORECTX, "Certificate store error")                      \
    f(ERR_SCM_STOREINIT, "Cert store init error")                       \
    f(ERR_SCM_NOAKI, "Missing AKI")                                     \
    f(ERR_SCM_CRL, "CRL error")                                         \
    f(ERR_SCM_BADCRL, "Error reading CRL")                              \
    f(ERR_SCM_NOTIMPL, "Not implemented")                               \
    f(ERR_SCM_INVALASID, "Invalid AS number")                           \
    f(ERR_SCM_INVALSKI, "Invalid SKI")                                  \
    f(ERR_SCM_INVALIPB, "Invalid IP address block")                     \
    f(ERR_SCM_INVALIPL, "Invalid IP address length")                    \
    f(ERR_SCM_INVALVER, "Invalid version number")                       \
    f(ERR_SCM_INVALASN, "ASN.1 library error")                          \
    f(ERR_SCM_NOTEE, "Not an EE certificate")                           \
    f(ERR_SCM_BADFLAGS, "Invalid certificate flags")                    \
    f(ERR_SCM_BADCERTVERS, "Bad certificate version")                   \
    f(ERR_SCM_NCEXT, "Extension must be critical")                      \
    f(ERR_SCM_NOTCA, "Must be CA cert")                                 \
    f(ERR_SCM_BADPATHLEN, "Pathlen invalid")                            \
    f(ERR_SCM_NOBC, "Missing basic constraints")                        \
    f(ERR_SCM_DUPBC, "Duplicate basic constraints")                     \
    f(ERR_SCM_ISCA, "Cannot be CA cert")                                \
    f(ERR_SCM_CEXT, "Extension cannot be critical")                     \
    f(ERR_SCM_NOSKI, "Missing SKI")                                     \
    f(ERR_SCM_DUPSKI, "Duplicate SKI")                                  \
    f(ERR_SCM_ACI, "authCertIssuer present")                            \
    f(ERR_SCM_ACSN, "AuthCertSN present")                               \
    f(ERR_SCM_DUPAKI, "Duplicate AKI")                                  \
    f(ERR_SCM_NOKUSAGE, "Missing key usage")                            \
    f(ERR_SCM_DUPKUSAGE, "Duplicate key usage")                         \
    f(ERR_SCM_CRLDPTA, "CRLDP in TA cert")                              \
    f(ERR_SCM_NOCRLDP, "Missing CRLDP")                                 \
    f(ERR_SCM_DUPCRLDP, "Duplicate CRLDP")                              \
    f(ERR_SCM_CRLDPSF, "CRLDP with subfields")                          \
    f(ERR_SCM_CRLDPNM, "Cannot get CRLDP name field")                   \
    f(ERR_SCM_BADCRLDP, "CRLDP not a URI")                              \
    f(ERR_SCM_NOAIA, "Missing AIA")                                     \
    f(ERR_SCM_DUPAIA, "Duplicate AIA")                                  \
    f(ERR_SCM_BADAIA, "AIA not a URI")                                  \
    f(ERR_SCM_NOSIA, "Missing SIA")                                     \
    f(ERR_SCM_DUPSIA, "Duplicate SIA")                                  \
    f(ERR_SCM_BADSIA, "SIA not a URI")                                  \
    f(ERR_SCM_NOPOLICY, "Missing policy ext")                           \
    f(ERR_SCM_DUPPOLICY, "Duplicate policy ext")                        \
    f(ERR_SCM_POLICYQ, "Invalid policy qualifiers")                     \
    f(ERR_SCM_BADOID, "Invalid OID")                                    \
    f(ERR_SCM_NOIPAS, "Missing RFC3779 ext")                            \
    f(ERR_SCM_DUPIP, "Duplicate IP resources")                          \
    f(ERR_SCM_DUPAS, "Duplicate AS# resources")                         \
    f(ERR_SCM_INVALSIG, "Invalid signature")                            \
    f(ERR_SCM_HSSIZE, "Hashable string size error")                     \
    f(ERR_SCM_HSREAD, "Hashable string read error")                     \
    f(ERR_SCM_BADAF, "Bad address family")                              \
    f(ERR_SCM_BADDA, "Bad digest algorithm")                            \
    f(ERR_SCM_BADCT, "Bad Content type")                                \
    f(ERR_SCM_UNSIGATTR, "Unsigned attributes")                         \
    f(ERR_SCM_INVALFAM, "Invalid IP family")                            \
    f(ERR_SCM_NOSIG, "No signature")                                    \
    f(ERR_SCM_DUPSIG, "Duplicate signature")                            \
    f(ERR_SCM_BADMKHASH, "Error creating hash")                         \
    f(ERR_SCM_BADFAH, "Error in FileAndHash")                           \
    f(ERR_SCM_BADNUMCERTS, "Wrong number of certificates")              \
    f(ERR_SCM_BADDATES, "Invalid dates")                                \
    f(ERR_SCM_BADALG, "Differing algorithms in cert")                   \
    f(ERR_SCM_BCPRES, "Basic constraints in EE cert")                   \
    f(ERR_SCM_BADSIGINFO, "Error in SignerInfos")                       \
    f(ERR_SCM_INVALROA, "Invalid ROA")                                  \
    f(ERR_SCM_INVALMAN, "Invalid manifest")                             \
    f(ERR_SCM_WRITE_EE, "Error writing EE cert")                        \
    f(ERR_SCM_SMALLKEY, "Key too small")                                \
    f(ERR_SCM_ASN1_LTH, "Invalid indefinite ASN.1 length")              \
    f(ERR_SCM_EXPIRED, "Certificate expired")                           \
    f(ERR_SCM_BADSUBJECT, "Invalid subject name")                       \
    f(ERR_SCM_BADISSUER, "Invalid issuer name")                         \
    f(ERR_SCM_INVALAKI, "Invalid AKI")                                  \
    f(ERR_SCM_CRLDPNMRS, "No rsync URI in CRLDP")                       \
    f(ERR_SCM_BADSERNUM, "Bad serial number")                           \
    f(ERR_SCM_HASCRL, "Should not have CRL")                            \
    f(ERR_SCM_CRYPTLIB, "Error starting Cryptlib")                      \
    f(ERR_SCM_BADHASHALG, "Bad hash algorithm")                         \
    f(ERR_SCM_BADNUMDALG, "Bad number of digest algorithms")            \
    f(ERR_SCM_NUMSIGINFO, "Bad number of signer infos")                 \
    f(ERR_SCM_SIGINFOVER, "Invalid signer infos version")               \
    f(ERR_SCM_SIGINFOSID, "Invalid signer info sid")                    \
    f(ERR_SCM_SIGINFOTIM, "Invalid signer info time")                   \
    f(ERR_SCM_BADCMSVER, "Invalid CMS version")                         \
    f(ERR_SCM_BADMSGDIGEST, "Invalid message digest")                   \
    f(ERR_SCM_BADSIGATTRS, "Invalid signed attributes")                 \
    f(ERR_SCM_BADCONTTYPE, "Invalid content type")                      \
    f(ERR_SCM_BINSIGTIME, "Invalid binary signing time")                \
    f(ERR_SCM_BADSIGALG, "Invalid signature algorithm")                 \
    f(ERR_SCM_BADROAVER, "Invalid ROA version")                         \
    f(ERR_SCM_BADMANVER, "Invalid manifest version")                    \
    f(ERR_SCM_BADASRANGE, "Invalid AS numbers")                         \
    f(ERR_SCM_BADASNUM, "AS number outside range")                      \
    f(ERR_SCM_NOIPADDR, "No IP addresses")                              \
    f(ERR_SCM_NOASNUM, "No AS number")                                  \
    f(ERR_SCM_ROAIPMISMATCH, "ROA IP addresses not in EE")              \
    f(ERR_SCM_IPTOUCH, "IP addresses overlap")                          \
    f(ERR_SCM_BADMFTHASH, "Bad hash in manifest")                       \
    f(ERR_SCM_BADDIGEST, "Invalid digest in CMS")                       \
    f(ERR_SCM_BADMFTDBHASH, "Wrong manifest hash in DB")                \
    f(ERR_SCM_NOCRLVER, "Missing CRL version")                          \
    f(ERR_SCM_BADCRLVER, "Wrong CRL version")                           \
    f(ERR_SCM_CRLENTRYEXT, "CRL Entry Extension present")               \
    f(ERR_SCM_BADMFTFILENAME, "Invalid filename in manifest")           \
    f(ERR_SCM_BADREVDATE, "Invalid revocation date")                    \
    f(ERR_SCM_BADREVSNUM, "Invalid revoked serial number")              \
    f(ERR_SCM_NOCRLNUM, "No CRL number extension")                      \
    f(ERR_SCM_BADMFTNUM, "Invalid manifest number")                     \
    f(ERR_SCM_MFTDUPFILE, "Duplicate file in manifest")                 \
    f(ERR_SCM_EKU, "EKU erroneously present")                           \
    f(ERR_SCM_UNSUPPUBKEY, "Unsupported Public Key Info")               \
    f(ERR_SCM_BADASRDI, "Routing Domain Identifier(s) present")         \
    f(ERR_SCM_BADCRLNUM, "Invalid CRLNumber")                           \
    f(ERR_SCM_NOIPEXT, "Missing RFC3779 IP extension")                  \
    f(ERR_SCM_REVOKED, "Object has been revoked")                       \
    f(ERR_SCM_NOTINHERIT, "Non-inherit resources present")              \
    f(ERR_SCM_BADCHAR, "Invalid character sequence")                    \
    f(ERR_SCM_AIATA, "AIA in TA cert")                                  \
    f(ERR_SCM_INVALSATTR, "Invalid signed attribute")                   \
    f(ERR_SCM_TAINHERIT, "TA cert has inherit resources")               \
    f(ERR_SCM_TRUNCATED, "Truncated data")                              \
    f(ERR_SCM_BREAK, "Stop iteration (no error)")                       \
    // end of error codes list

#define ERROR_ENUM_POS(NAME, DESCR) POS_##NAME,
#define ERROR_ENUM(NAME, DESCR) NAME = -POS_##NAME,

/**
 * @brief
 *     helper enum to make it easier to create the err_code enum
 *
 * do not use this -- use the ::err_code enum entries instead
 */
enum {
    ERROR_CODES(ERROR_ENUM_POS)
    POS_ERR_SCM_MAXERR_PLUS_ONE // this must be last
};

/**
 * @brief
 *     error codes (and one success code)
 *
 * Only zero (::ERR_SCM_NOERR) is a success code; all other values
 * indicate an error.
 *
 * All values in this enum are guaranteed to be non-positive.
 *
 * @warning
 *     Assuming the function that sets the error code does not
 *     intentionally use positive values for non-error purposes, code
 *     should test `foo != 0`, not `foo < 0`, when checking for
 *     errors.  This avoids tricky problems if a bug causes a function
 *     to accidentally yield a positive value.
 *
 * @warning
 *     While the C standard says that enumeration constants have type
 *     `int` (C99 6.4.4.3p2, 6.7.2.2p3), an enumeration type may be
 *     smaller or bigger than an `int` (and may be unsigned) as long
 *     as the enumeration type can represent all of its members (C99
 *     6.7.2.2p4).  Thus, `sizeof(int)` might not equal
 *     `sizeof(err_code)`, and code should not pass the address of an
 *     ::err_code to a function that takes a pointer to an `int` (and
 *     vice-versa).
 *
 * @warning
 *     Care should be taken when using these error codes for the exit
 *     status of a utility.  For determining exit status from shell
 *     scripts, POSIX Issue 7 TC1 XCU Section 2.8.2 essentially says
 *     that the return value of a utility is computed by taking the 8
 *     least significant bits of the exit status (the value passed to
 *     _Exit(), _exit(), or exit() or returned from main()).  Thus,
 *     the exit status is effectively cast to a uint8_t before being
 *     returned.  If there are any error codes less than -255, those
 *     error codes will be misinterpreted.  In particular, if a
 *     utility exits using an error code that happens to have the
 *     value -256 (or -512, etc.), the utility effectively returns 0
 *     (success).
 */
typedef enum {
    ERROR_CODES(ERROR_ENUM)
    /** @brief the value of the most negative error code */
    ERR_SCM_MAXERR = -(POS_ERR_SCM_MAXERR_PLUS_ONE - 1)
} err_code;

/*
 * macro that prints an error string and call return if a condition is true
 */
#define checkErr(test, ...)                                             \
    do {                                                                \
        if (test) {                                                     \
            LOG(LOG_ERR, __VA_ARGS__);                                  \
            return ERR_SCM_UNSPECIFIED;                                 \
        }                                                               \
    } while (0)

/**
 * @brief
 *     log a message and abort if @p test is non-0
 *
 * @param[in] test
 *     An expression of type @c err_code to check.  If non-zero,
 *     abort() is called.
 */
#define assertOK(test)                                                  \
    do {                                                                \
        err_code assertOK_test = (test);                                \
        if (assertOK_test) {                                            \
            LOG(LOG_CRIT,                                               \
                "unexpected error at %s:%i: %s %s",                     \
                __FILE__,                                               \
                __LINE__,                                               \
                err2name(assertOK_test),                                \
                err2string(assertOK_test));                             \
            LOG(LOG_CRIT, "failed expression: %s", #test);              \
            FLUSH_LOG();                                                \
            abort();                                                    \
        }                                                               \
    } while (0)

/**
 * @brief
 *     get the human-friendly description of an error code
 */
const char *
err2string(
    err_code err);

/**
 * @brief
 *     get the name of an error given its error code
 */
const char *
err2name(
    err_code err);

#endif
