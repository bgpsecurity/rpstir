
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "casn/casn.h"
#include "rpki-asn1/cms.h"
#include "rpki-asn1/crlv2.h"
#include "util/logging.h"

#define MSG_USAGE "Usage: name of input file"
#define MSG_SUFFIX "Suffix missing in %s"
#define MSG_TYPE "Unknown type %s"
#define MSG_READ "Error reading at %s"

int main(
    int argc,
    char **argv)
{
    struct CMS cms;
    struct Certificate certificate;
    struct CertificateRevocationList crl;
    char *buf;
    int bsize;


    if (argc < 2)
        DONE(MSG_USAGE);
    char *p = strrchr(argv[1], (int)'.');
    if (!p)
        FATAL(MSG_SUFFIX, argv[1]);
    if (!strcmp(p, ".cer"))
    {
        Certificate(&certificate, (ushort) 0);
        if (get_casn_file(&certificate.self, argv[1], 0) < 0)
            FATAL(MSG_READ, casn_err_struct.asn_map_string);
        bsize = dump_size(&certificate.self);
        buf = (char *)calloc(1, bsize + 8);
        dump_casn(&certificate.self, buf);
        printf("%s", buf);
        free(buf);
        delete_casn(&certificate.self);
    }
    else if (!strcmp(p, ".crl"))
    {
        CertificateRevocationList(&crl, (ushort) 0);
        if (get_casn_file(&crl.self, argv[1], 0) < 0)
            FATAL(MSG_READ, casn_err_struct.asn_map_string);
        bsize = dump_size(&crl.self);
        buf = (char *)calloc(1, bsize + 8);
        dump_casn(&crl.self, buf);
        printf("%s", buf);
        free(buf);
        delete_casn(&crl.self);
    }
    else if (!strcmp(p, ".man") || !strcmp(p, ".mft") || !strcmp(p, ".mnf") ||
             !strcmp(p, ".roa") ||
             !strcmp(p, ".gbr"))
    {
        CMS(&cms, (ushort) 0);
        if (get_casn_file(&cms.self, argv[1], 0) < 0)
            FATAL(MSG_READ, casn_err_struct.asn_map_string);
        bsize = dump_size(&cms.self);
        buf = (char *)calloc(1, bsize + 8);
        dump_casn(&cms.self, buf);
        printf("%s", buf);
        free(buf);
        delete_casn(&cms.self);
    }
    else
        FATAL(MSG_TYPE, p);
    return 0;
}
