#ifndef _LIB_RPKI_OBJECT_CRL_H
#define _LIB_RPKI_OBJECT_CRL_H

#include "rpki-asn1/crlv2.h"


/**
 * Sign a CRL.
 * @return NULL on success, error message on failure
 */
const char *signCRL(
    struct CertificateRevocationList *crlp,
    const char *keyfile);

#endif
