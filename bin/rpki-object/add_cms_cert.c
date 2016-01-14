#include <stdio.h>
#include <util/cryptlib_compat.h>
#include <rpki-asn1/keyfile.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <rpki-object/certificate.h>
#include <rpki-object/cms/cms.h>
#include <casn/casn.h>
#include <util/hashutils.h>
#include "util/logging.h"

#define MSG_OK "Finished OK"
#define MSG_GET "Couldn't get %s"
#define MSG_INSERT "Error inserting %s"     // 2
#define MSG_NO_AKI "EEcert has no key identifier"
#define MSG_SIGN "Error signing in %s"

struct keyring {
    char filename[80];
    char label[20];
    char password[20];
};

static struct keyring keyring;


int main(
    int argc,
    char **argv)
{
    struct CMS cms;
    CMS(&cms, (ushort) 0);
    if (argc < 4 || argc > 5)
    {
        fprintf(stderr, "Usage: %s EEcert CMSfile EEkeyfile [outfile]\n",
                argv[0]);
        fprintf(stderr,
                "If the environment variable RPKI_NO_SIGNING_TIME is set,\n");
        fprintf(stderr, "the signing time won't be set.\n");
        return -1;
    }
    strcpy(keyring.label, "label");
    strcpy(keyring.password, "password");
    struct Certificate EEcert;
    Certificate(&EEcert, (ushort) 0);
    // get the EE cert
    if (get_casn_file(&EEcert.self, argv[1], 0) < 0)
        FATAL(MSG_GET, "EE certificate");
    // get the CMS object
    if (get_casn_file(&cms.self, argv[2], 0) < 0)
        FATAL(MSG_GET, "CMS file");
    struct Extension *sextp;
    // get EE's Auth Key ID
    if (!(sextp = find_extension(&EEcert.toBeSigned.extensions, id_authKeyId, false)))
        FATAL(MSG_NO_AKI);
    // add cert to CMS object
    struct SignedData *signedDatap = &cms.content.signedData;
    struct Certificate *certp;
    clear_casn(&signedDatap->certificates.self);
    certp =
        (struct Certificate *)inject_casn(&signedDatap->certificates.self, 0);
    if (!certp)
        FATAL(MSG_INSERT, "EE certificate");
    copy_casn(&certp->self, &EEcert.self);
    num_items(&signedDatap->certificates.self);
    // check CMS suffix
    char *c = strrchr(argv[2], (int)'.');
    if (!c || (strcmp(c, ".roa") && strcmp(c, ".man") && strcmp(c, ".mft") &&
               strcmp(c, ".mnf")))
        FATAL(MSG_GET, "CMSfile suffix");
    // sign it!
    const char *msg = signCMS(&cms, argv[3], 0);
    if (msg)
        fprintf(stderr, "%s\n", msg);
    else                        // and write it
    if (argc < 5)
        put_casn_file(&cms.self, (char *)0, 1);
    else
        put_casn_file(&cms.self, argv[4], 0);
    return 0;
}
