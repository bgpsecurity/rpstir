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

#define MSG_SIG "Signature %s"
#define MSG_USAGE "Args are locertfile hicertfile"
#define MSG_GET "Can't get %s"
#define MSG_SIG_ERR "Signing error in %s"

int main(
    int argc,
    char **argv)
{
    OPEN_LOG("cert_validate", LOG_USER);
    if (argc != 3)
        FATAL(MSG_USAGE);
    struct Certificate locert,
        hicert;
    Certificate(&locert, (ushort) 0);
    Certificate(&hicert, (ushort) 0);
    if (get_casn_file(&locert.self, argv[1], 0) < 0)
        FATAL(MSG_GET, argv[1]);
    if (get_casn_file(&hicert.self, argv[2], 0) < 0)
        FATAL(MSG_GET, argv[2]);
    if (!check_cert_signature(&locert, &hicert))
        FATAL(MSG_SIG, "Failed");
    DONE(MSG_SIG, "succeeded");
    return 0;
}
