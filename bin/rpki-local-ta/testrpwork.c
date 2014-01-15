/*
 * $Id: rcli.c 836 2008-12-29 20:32:04Z cgardiner $ 
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <getopt.h>
#include <time.h>
#include <netdb.h>
#ifdef __NetBSD__
#include <netinet/in.h>
#endif
#ifdef __FreeBSD__
#include <netinet/in.h>
#endif

#include "util/logging.h"
#include "config/config.h"
#include "rpki/scm.h"
#include "rpki/scmf.h"
#include "rpki/sqhl.h"
#include "rpki/diru.h"
#include "rpki/myssl.h"
#include "rpki/err.h"

int main(
    int argc,
    char **argv)
{
    scm *scmp = NULL;
    scmcon *conp = NULL;
    scmtab *table = NULL;
    char errMsg[1024];

    OPEN_LOG("testrpwork", LOG_USER);

    if (!my_config_load())
    {
        FATAL("Can't load configuration");
    }

    if ((scmp = initscm()) == NULL)
        FATAL("Can't initialize database");
    if ((conp = connectscm(scmp->dsn, errMsg, 1024)) == NULL)
        FATAL("Can't connect");
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    if (!(table = findtablescm(scmp, "certificate")))
        FATAL("Can't get table");
    if (argc != 2)
        FATAL("Need name of control file");
    int ansr = read_SKI_blocks(scmp, conp, argv[1]);
    if (ansr < 0)
        fprintf(stderr, "Had error %d: %s\n", ansr, err2string(ansr));
    config_unload();
    CLOSE_LOG();
    DONE("Finished");
    return 0;
}
