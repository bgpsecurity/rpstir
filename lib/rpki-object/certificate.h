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

#endif
