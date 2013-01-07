/*
 * $Id: make_TA.c c 506 2008-06-03 21:20:05Z gardiner $ 
 */


#include <stdio.h>
#include <util/cryptlib_compat.h>
#include <rpki-asn1/keyfile.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <rpki-object/certificate.h>
#include <rpki-object/cms/cms.h>
#include <rpki-asn1/roa.h>
#include <casn/casn.h>
#include <util/hashutils.h>

char *msgs[] = {
    "Finished OK\n",
    "Couldn't get %s\n",
    "Error inserting %s\n",     // 2
    "EEcert has no key identifier\n",
    "Error signing in %s\n",
};

static void fatal(
    int err,
    char *paramp)
{
    fprintf(stderr, msgs[err], paramp);
    exit(err);
}

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
    struct ROA roa;
    ROA(&roa, (ushort) 0);
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
        fatal(1, "EE certificate");
    // get the CMS object
    if (get_casn_file(&roa.self, argv[2], 0) < 0)
        fatal(1, "CMS file");
    struct Extension *sextp;
    // get EE's Auth Key ID
    if (!(sextp = find_extension(&EEcert.toBeSigned.extensions, id_authKeyId, false)))
        fatal(3, "key identifier");
    // add cert to CMS object 
    struct SignedData *signedDatap = &roa.content.signedData;
    struct Certificate *certp;
    clear_casn(&signedDatap->certificates.self);
    certp =
        (struct Certificate *)inject_casn(&signedDatap->certificates.self, 0);
    if (!certp)
        fatal(2, "EE certificate");
    copy_casn(&certp->self, &EEcert.self);
    num_items(&signedDatap->certificates.self);
    // check CMS suffix
    char *c = strrchr(argv[2], (int)'.');
    if (!c || (strcmp(c, ".roa") && strcmp(c, ".man") && strcmp(c, ".mft") &&
               strcmp(c, ".mnf")))
        fatal(1, "CMSfile suffix");
    // sign it!
    char *msg = signCMS(&roa, argv[3], 0);
    if (msg)
        fprintf(stderr, "%s\n", msg);
    else                        // and write it
    if (argc < 5)
        put_casn_file(&roa.self, (char *)0, 1);
    else
        put_casn_file(&roa.self, argv[4], 0);
    return 0;
}
