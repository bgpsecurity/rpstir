#ifndef _LIB_RPKI_OBJECT_CERTIFICATE_H
#define _LIB_RPKI_OBJECT_CERTIFICATE_H

#include <stdbool.h>

#include "rpki-asn1/certificate.h"


/**
 * Find an extension by oid, optionally creating it it's not found and if
 * create is true. Returns NULL if no extension is found or created, or if
 * there's an error.
 */
struct Extension *find_extension(
    struct Extensions *extsp,
    const char *oid,
    bool create);

/**
 * If an extension with the specified oid exists, clear it and return it.
 * Otherwise, create a new extension with the specified oid.
 *
 * @return the extension, or NULL on error
 */
struct Extension *make_extension(
    struct Extensions *extsp,
    const char *oid);

/**
 * Check the signature of an object signed by a certificate.
 *
 * @param locertp signed object (NOTE: does not have to be part of a cert)
 * @param hicertp parent certificate
 * @param sigp signature
 * @return true on valid signature, false on invalid signature or error
 */
bool check_signature(
    struct casn *locertp,
    struct Certificate *hicertp,
    struct casn *sigp);

/**
 * Like check_signature() above, but with a child that's a certificate.
 */
bool check_cert_signature(
    struct Certificate *locertp,
    struct Certificate *hicertp);

/**
 * Write the hash of keyp to valuep.
 *
 * @param bad whether or not to write an invalid hash
 */
int writeHashedPublicKey(
    struct casn *valuep,
    struct casn *keyp,
    bool bad);

#endif
