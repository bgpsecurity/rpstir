#ifndef _LIB_RPKI_OBJECT_SIGNATURE_H
#define _LIB_RPKI_OBJECT_SIGNATURE_H

#include <stdbool.h>

#include "casn/casn.h"

/**
 * Create a signature.
 *
 * @param[in] content ASN.1 structure to sign
 * @param[out] signature ASN.1 structure to put the signature into
 * @param[in] keyfile file containing the key to sign with
 * @param[in] label keyfile's label
 * @param[in] password keyfiles's password
 * @param[in] bad whether or not to make the signature invalid
 * @return true on success, false on failure
 */
bool set_signature(
    struct casn *content,
    struct casn *signature,
    const char *keyfile,
    const char *label,
    const char *password,
    bool bad);


#endif
