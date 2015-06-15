/**
 * sign_cms - bare-bones CMS signing tool
 *
 * This is a bare-bones CMS signing tool.  It does NOT hash the
 * encapContentInfo to set the message digest in the signedAttrs
 * field.  It simply takes as input a user-provided private key and
 * the already-constructed signedAttrs.  It just hashes signedAttrs,
 * computes the RSA signature, and sets a signature value in the
 * SignerInfo.
 *
 * Exception: if signedAttrs field is absent, the first paragraph of
 * RFC 5652 section 5.4 is implemented.  That is, hash the eContent
 * value.
 */

#include <stdio.h>
#include <util/cryptlib_compat.h>
#include <stdlib.h>
#include "rpki-asn1/roa.h"
#include "util/logging.h"
#include "rpki-object/cms/cms.h"


int main(
    int argc,
    char **argv)
{
    const char *cmsfilename = NULL;     /* to-be-signed CMS file */
    const char *keyfilename = NULL;     /* p15 key file */
    const char *errmsg = NULL;
    struct CMSBlob cms;

    if (cryptInit() != CRYPT_OK)
    {
        LOG(LOG_ERR, "could not initialize cryptlib");
        return -1;
    }

    /*
     * parse arguments 
     */
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s cmsfile keyfile\n", argv[0]);
        return -1;
    }
    cmsfilename = argv[1];
    keyfilename = argv[2];

    /*
     * read CMS file 
     */
    CMSBlob(&cms, (ushort) 0);
    if (get_casn_file(&cms.self, (char *)cmsfilename, 0) < 0)
    {
        LOG(LOG_ERR, "could not load %s", cmsfilename);
        return -1;
    }

    /*
     * sign CMS 
     */
    errmsg = signCMSBlob(&cms, keyfilename);
    if (errmsg)
    {
        LOG(LOG_ERR, "error %s", errmsg);
        return -1;
    }

    /*
     * write CMS file 
     */
    if (put_casn_file(&cms.self, (char *)cmsfilename, 0) < 0)
    {
        LOG(LOG_ERR, "could not write %s", cmsfilename);
        return -1;
    }

    delete_casn(&cms.self);

    return 0;
}
