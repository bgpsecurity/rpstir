#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <util/cryptlib_compat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <util/file.h>
#include <rpki-asn1/certificate.h>
#include <rpki-asn1/extensions.h>
#include <rpki-object/cms/cms.h>
#include <rpki/cms/roa_utils.h>
#include <assert.h>

void usage(
    char *prog)
{
    printf("usage:\n");
    printf("%s -o file [-b]\n", prog);
    printf("  -o file: file to write ghostbusters to\n");
    printf("  -b: generate bad (invalid) signature\n");
    printf(" other file names are derived, e.g. for G123.gbr:\n");
    printf("  certificate file C12G3.cer, parent file C12.cer,\n");
    printf("  keyfile C12G3.p15.\n");
    exit(1);
}

char *msgs[] = {
    "unused 1\n",               // 0
    "IPAddress block has range\n",
    "Can't read %s\n",          // 2
    "Can't find %s extension in certificate\n",
    "Error writing %s\n",       // 4
    "Can't find extension %s\n",
    "Can't find ASNum[%d]\n",   // 6
    "Signature failed in %s\n",
};

void fatal(
    int err,
    ...)
{
    va_list ap;
    va_start(ap, err);
    assert(err >= 0);
    assert((size_t)err < (sizeof(msgs) / sizeof(msgs[0])));
    vfprintf(stderr, msgs[err], ap);
    va_end(ap);
    exit(err);
}

static void make_fulldir(
    char *fulldir,
    const char *locpath)
{
    // GBR goes in issuer's directory, e.g.
    // G1.gbr goes nowhere else,
    // G11.gbr goes into C1/,
    // G121.gbr goes into C1/2
    // G1231.gbr goes into C1/2/3
    char *f = fulldir;
    const char *l = locpath;
    if (strlen(locpath) > 6)
    {
        *f++ = 'C';
        l++;
        *f++ = *l++;            // 1st digit
        *f++ = '/';
        if (l[1] != '.')        // 2nd digit
        {
            *f++ = *l++;
            *f++ = '/';
            if (l[1] != '.')    // 3rd digit
            {
                *f++ = *l++;
                *f++ = '/';
                if (l[1] != '.')        // 4th digit
                {
                    *f++ = *l++;
                    *f++ = '/';
                }
            }
        }
    }
}

static void make_fullpath(
    char *fullpath,
    const char *locpath)
{
    make_fulldir(fullpath, locpath);
    strcat(fullpath, locpath);
}

int main(
    int argc,
    char **argv)
{
    bool bad_signature = false;
    char *certfile = NULL,
        *gbrfile = NULL,
        *keyfile = NULL,
        *pcertfile = NULL;
    struct CMS cms;
    struct Certificate cert,
        pcert;
    const char *msg;
    int c;

    while ((c = getopt(argc, argv, "bo:")) != -1)
    {
        switch (c)
        {
        case 'o':
            // output file
            gbrfile = strdup(optarg);
            certfile = (char *)calloc(1, strlen(gbrfile) + 4);
            strcpy(certfile, gbrfile);
            *certfile = 'C';
            char *b = strchr(certfile, (int)'.');
            b -= 1;             // points to where 'G' should go
            char *c;
            for (c = certfile; *c; c++);
            for (c--; c >= b; c[1] = *c, c--);
            *b = 'G';
            strcpy(strchr(certfile, (int)'.'), ".cer");
            pcertfile = (char *)calloc(1, strlen(certfile) + 8);
            char *p = strchr(certfile, (int)'G');
            strncpy(pcertfile, certfile, p - certfile);
            strcat(pcertfile, &p[2]);
            keyfile = (char *)calloc(1, strlen(certfile) + 2);
            strcpy(keyfile, certfile);
            strcpy(strchr(keyfile, (int)'.'), ".p15");
            break;

        case 'b':
            bad_signature = true;
            break;

        default:
            fprintf(stderr, "illegal option.\n");
            usage(argv[0]);
        }
    }

    // validate arguments
    if (gbrfile == NULL || certfile == NULL || keyfile == NULL)
    {
        fprintf(stderr, "missing output file\n");
        usage(argv[0]);
    }

    // init cms
    CMS(&cms, 0);
    write_objid(&cms.contentType, id_signedData);

    // init and read in the ee cert
    Certificate(&cert, 0);
    if (get_casn_file(&cert.self, certfile, 0) < 0)
        fatal(2, certfile);

    // init and read in the parent cert
    Certificate(&pcert, 0);
    if (get_casn_file(&pcert.self, pcertfile, 0) < 0)
        fatal(2, pcertfile);

    // mark the gbr: the signed data is hashed with sha256
    struct SignedData *sgdp = &cms.content.signedData;
    write_casn_num(&sgdp->version.self, 3);
    struct CMSAlgorithmIdentifier *algidp =
        (struct CMSAlgorithmIdentifier *)inject_casn(&sgdp->digestAlgorithms.
                                                     self, 0);
    write_objid(&algidp->algorithm, id_sha256);
    write_casn(&algidp->parameters.sha256, (uchar *) "", 0);

    // insert the EE's cert
    struct Certificate *sigcertp =
        (struct Certificate *)inject_casn(&sgdp->certificates.self, 0);
    copy_casn(&sigcertp->self, &cert.self);

    // mark the encapsulated content as a ROA
    write_objid(&sgdp->encapContentInfo.eContentType,
                id_ct_rpkiGhostbusters);

    // fill in the vCard
    const char vcard[] =
        "BEGIN:VCARD\r\n"
        "VERSION:4.0\r\n"
        "FN:Bob\r\n"
        "ORG:Bob's House of Pizza\r\n"
        "EMAIL:bob+extra-cheese@example.com\r\n"
        "END:VCARD\r\n";
    write_casn(&sgdp->encapContentInfo.eContent.ghostbusters, (uchar *)vcard,
               sizeof(vcard) - 1);
    unsigned char *foo;
    int lth = readvsize_casn(&sgdp->encapContentInfo.eContent.ghostbusters, &foo);
    write(STDOUT_FILENO, foo, (size_t) lth);

    // sign the message
    msg = signCMS(&cms, keyfile, bad_signature);
    if (msg != NULL)
        fatal(7, msg);

    // validate: make sure we did it all right
    if (ghostbustersValidate(&cms) != 0)
        fprintf(stderr, "Warning: %s failed ghostbustersValidate (-b option %s) \n",
                gbrfile, (bad_signature ? "not set" : "set"));

    // write out the gbr
    char fulldir[40];
    char fullpath[40];
    memset(fullpath, 0, sizeof(fullpath));
    memset(fulldir, 0, sizeof(fulldir));
    make_fulldir(fulldir, gbrfile);
    make_fullpath(fullpath, gbrfile);
    printf("Path: %s\n", fullpath);
    if (!mkdir_recursive(fulldir, 0777))
    {
        fprintf(stderr, "error: mkdir_recursive(\"%s\"): %s\n", fulldir,
                strerror(errno));
        fatal(4, fulldir);
    }
    if (put_casn_file(&cms.self, gbrfile, 0) < 0)
        fatal(4, gbrfile);
    if (put_casn_file(&cms.self, fullpath, 0) < 0)
        fatal(4, fullpath);

    fprintf(stderr, "Finished %s OK\n", gbrfile);
    return 0;
}
