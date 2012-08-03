/*
 * $Id: roa_validate.c 506 2008-06-03 21:20:05Z csmall $ 
 */


#include <assert.h>

#include "util/logging.h"
#include "rpki/cms/roa_utils.h"
#include "util/hashutils.h"
#include "util/cryptlib_compat.h"
#include "rpki-object/certificate.h"

/*
 * This file contains the functions that semantically validate the ROA. Any
 * and all syntactic validation against existing structures is assumed to have 
 * been performed at the translation step (see roa_serialize.c). 
 */
#define MINMAXBUFSIZE 20

char *msgs[] = {
    "Signature %s\n",
    "Args are locertfile hicertfile\n",
    "Can't get %s\n",
    "Signing error in %s\n",
};

static void fatal(
    int err,
    char *param)
{
    fprintf(stderr, msgs[err], param);
    exit(err);
}

int main(
    int argc,
    char **argv)
{
    OPEN_LOG("cert_validate", LOG_USER);
    if (argc != 3)
        fatal(1, (char *)0);
    struct Certificate locert,
        hicert;
    Certificate(&locert, (ushort) 0);
    Certificate(&hicert, (ushort) 0);
    if (get_casn_file(&locert.self, argv[1], 0) < 0)
        fatal(2, argv[1]);
    if (get_casn_file(&hicert.self, argv[2], 0) < 0)
        fatal(2, argv[2]);
    if (!check_cert_signature(&locert, &hicert))
        fatal(0, "Failed");
    fatal(0, "succeeded");
    return 0;
}
