#ifndef _LIB_RPKI_OBJECT_CMS_H
#define _LIB_RPKI_OBJECT_CMS_H

#include <stdbool.h>

#include "rpki-asn1/cms.h"


/**
 * Sign a CMS.
 * @param bad whether or not to generate an incorrect signature.
 * @return NULL on success, error message on failure
 */
const char *signCMS(
    struct CMS *cms,
    const char *keyfilename,
    bool bad);

/**
 * sign CMS blob blindly, neither verifying eContent nor touching signedAttrs
 * @param cms signed object with one signerInfo (the one to be signed)
 * @param keyfilename path to .p15 keyfile
 * @return NULL on success, error message on failure
 */
const char *signCMSBlob(
    struct CMSBlob *cms,
    const char *keyfilename);

#endif
