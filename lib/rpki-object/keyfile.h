#ifndef _LIB_RPKI_OBJECT_KEYFILE_H
#define _LIB_RPKI_OBJECT_KEYFILE_H

#include <stdbool.h>

#include "rpki-asn1/keyfile.h"

/**
 * Copy the key from keyfile to spkp.
 *
 * @return true on success, false on failure
 */
bool fillPublicKey(
    struct casn *spkp,
    const char *keyfile);

#endif
