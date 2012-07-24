
#include <stdio.h>
#include <util/cryptlib_compat.h>
#include <rpki-asn1/keyfile.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <rpki-asn1/certificate.h>
#include <rpki-asn1/crlv2.h>
#include <rpki-asn1/roa.h>
#include <rpki-asn1/manifest.h>
#include <rpki-object/signature.h>
#include <casn/casn.h>
#include <util/hashutils.h>
#include "create_object.h"

struct keyring {
    char filename[1024];        // expanded from 80 to 1024. it was cutting
                                // off filenames
    char label[10];
    char password[20];
} keyring;

/**
   sign_cert
   inputs:
       cert
       key file
   Returns
      0 = success
      <>0 error code
   Function
      Sign the ASN.1 encoded object using the private key from
      the file. Put the signature into the object.
*/

int sign_cert(
    struct Certificate *certp,
    char *keyname)
{
    struct AlgorithmIdentifier *algp,
       *tbsalgp;
    struct casn *casnp,
       *sigp,
       *selfp;
    int ret;


    selfp = &certp->self;
    casnp = &certp->toBeSigned.self;
    tbsalgp = &certp->toBeSigned.signature;
    sigp = &certp->signature;
    algp = &certp->algorithm;

    write_objid(&tbsalgp->algorithm, id_sha_256WithRSAEncryption);
    write_casn(&tbsalgp->parameters.rsadsi_SHA256_WithRSAEncryption,
               (uchar *) "", 0);
    strcpy(keyring.label, "label");
    strcpy(keyring.password, "password");
    strcpy(keyring.filename, keyname);
    if (!set_signature(casnp, sigp, keyring.filename, keyring.label,
                       keyring.password, false))
        return -1;

    write_objid(&algp->algorithm, id_sha_256WithRSAEncryption);
    write_casn(&algp->parameters.rsadsi_SHA256_WithRSAEncryption,
               (uchar *) "", 0);
    return 0;
}
