/*
 * $Id: make_manifest.c 453 2007-07-25 15:30:40Z gardiner $ 
 */


#include "rpki-asn1/manifest.h"
#include "rpki-asn1/roa.h"
#include "rpki-asn1/certificate.h"
#include "util/cryptlib_compat.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <casn/asn.h>
#include <casn/casn.h>
#include <util/hashutils.h>
#include <util/file.h>
#include "rpki-object/cms/cms.h"

/*
 * This file has a program to make manifests. 
 */

char *msgs[] = {
    "Finished %s OK\n",
    "Couldn't open %s\n",       // 1
    "Error reading %s\n",
    "Error adding %s\n",        // 3
    "Error inserting %s\n",
    "Error creating signature\n",       // 5
    "Error writing %s\n",
    "Signature failed in %s\n", // 7
    "Error getting %s\n",
};

static int fatal(
    int msg,
    char *paramp);

static int add_name(
    char *curr_file,
    struct Manifest *manp,
    int num,
    int bad)
{
    int fd,
        siz,
        hsiz;
    uchar *b,
        hash[40];
    if ((fd = open(curr_file, O_RDONLY)) < 0)
        fatal(1, curr_file);
    siz = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, 0);
    b = (uchar *) calloc(1, siz);
    if (read(fd, b, siz + 2) != siz)
        fatal(2, curr_file);
    hsiz = gen_hash(b, siz, hash, CRYPT_ALGO_SHA2);
    if (hsiz < 0)
        fatal(8, "hash");
    if (bad)
        hash[1]++;
    struct FileAndHash *fahp;
    if (!(fahp = (struct FileAndHash *)inject_casn(&manp->fileList.self, num)))
        fatal(3, "fileList");
    write_casn(&fahp->file, (uchar *) curr_file, strlen(curr_file));
    write_casn_bits(&fahp->hash, hash, hsiz, 0);
    return 1;
}

static int fatal(
    int msg,
    char *paramp)
{
    fprintf(stderr, msgs[msg], paramp);
    exit(msg);
}

static void make_fulldir(
    char *fulldir,
    const char *locpath)
{
    // Manifest goes in issuer's directory, e.g.
    // M1.man goes nowhere else, 
    // M11.man goes into C1/, 
    // M121.man goes into C1/2 
    // M1231.man goes into C1/2/3
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
    struct ROA roa;
    struct CMSAlgorithmIdentifier *algidp;
    ulong now = time((time_t *) 0);

    if (argc < 2)
    {
        printf("Usage: manifest name, data offset\n");
        return 0;
    }
    char manifestfile[40],
        certfile[40],
        keyfile[40];
    memset(manifestfile, 0, 40);
    memset(certfile, 0, 40);
    memset(keyfile, 0, 40);
    char *c;
    for (c = argv[1]; *c && *c != '.'; c++);
    *c = 0;
    strcat(strcpy(manifestfile, argv[1]), ".man");
    c--;
    int index;
    sscanf(c, "%d", &index);
    *c = 0;
    strcpy(certfile, argv[1]);
    certfile[0] = 'C';
    sprintf(&certfile[strlen(certfile)], "M%d.", index);
    strcpy(keyfile, certfile);
    strcat(certfile, "cer");
    strcat(keyfile, "p15");

    ROA(&roa, 0);
    write_objid(&roa.contentType, id_signedData);
    write_casn_num(&roa.content.signedData.version.self, (long)3);
    inject_casn(&roa.content.signedData.digestAlgorithms.self, 0);
    algidp =
        (struct CMSAlgorithmIdentifier *)member_casn(&roa.content.
                                                     signedData.digestAlgorithms.
                                                     self, 0);
    write_objid(&algidp->algorithm, id_sha256);
    write_casn(&algidp->parameters.sha256, (uchar *) "", 0);
    write_objid(&roa.content.signedData.encapContentInfo.eContentType,
                id_roa_pki_manifest);
    struct Manifest *manp =
        &roa.content.signedData.encapContentInfo.eContent.manifest;
    write_casn_num(&manp->manifestNumber, (long)index);
    int timediff = 0;
    if (argc == 3)
    {
        sscanf(argv[2], "%d", &timediff);
        char u = argv[2][strlen(argv[2]) - 1];
        if (u == 'h')
            timediff *= 60;
        else if (u == 'D')
            timediff *= (3600 * 24);
        else if (u == 'W')
            timediff *= (3600 * 24 * 7);
        else if (u == 'M')
            timediff *= (3600 * 24 * 30);
        else if (u == 'M')
            timediff *= (3600 * 24 * 365);
        else
            fatal(2, argv[2]);
        now += timediff;
    }
    write_casn_time(&manp->thisUpdate, now);
    now += (30 * 24 * 3600);
    write_casn_time(&manp->nextUpdate, now);
    write_objid(&manp->fileHashAlg, id_sha256);

    // now get the files 
    char curr_file[128];
    memset(curr_file, 0, 128);
    int num;
    for (num = 0; fgets(curr_file, 128, stdin) && curr_file[0] > ' '; num++)
    {
        char *a;
        int bad = 0;
        for (a = curr_file; *a && *a > ' '; a++);
        while (*a == ' ')
            a++;
        if (*a > ' ')
            bad = 1;
        for (a = curr_file; *a && *a > ' '; a++);
        if (*a <= ' ')
        {
            if (*curr_file == 'C')
                strcpy(a, ".cer");
            else if (*curr_file == 'L')
                strcpy(a, ".crl");
            else if (*curr_file == 'R')
                strcpy(a, ".roa");
        }
        else
        {
            while (*a > ' ')
                a++;
            *a = 0;             // bad hash flag and remove carriage return
        }
        add_name(curr_file, manp, num, bad);
    }
    if (!inject_casn(&roa.content.signedData.certificates.self, 0))
        fatal(4, "signedData");
    struct Certificate *certp =
        (struct Certificate *)member_casn(&roa.content.signedData.certificates.
                                          self, 0);
    if (get_casn_file(&certp->self, certfile, 0) < 0)
        fatal(2, certfile);
    if ((c = signCMS(&roa, keyfile, 0)))
        fatal(7, c);

    char fullpath[40];
    char fulldir[40];
    memset(fullpath, 0, sizeof(fullpath));
    memset(fulldir, 0, sizeof(fullpath));
    make_fulldir(fulldir, manifestfile);
    make_fullpath(fullpath, manifestfile);
    fprintf(stdout, "Path: %s\n", fullpath);
    if (fulldir[0] != '\0')
    {
        if (!mkdir_recursive(fulldir, 0777))
        {
            fprintf(stderr, "error: mkdir_recursive(\"%s\"): %s\n", fulldir,
                    strerror(errno));
            fatal(6, fulldir);
        }
    }

    if (put_casn_file(&roa.self, manifestfile, 0) < 0)
        fatal(6, manifestfile);
    if (put_casn_file(&roa.self, fullpath, 0) < 0)
        fatal(2, fullpath);
    for (c = manifestfile; *c && *c != '.'; c++);
    strcpy(c, ".raw");
    char *rawp;
    int lth = dump_size(&roa.self);
    rawp = (char *)calloc(1, lth + 4);
    dump_casn(&roa.self, rawp);
    int fd = open(manifestfile, (O_WRONLY | O_CREAT | O_TRUNC), (S_IRWXU));
    write(fd, rawp, lth);
    close(fd);
    free(rawp);
    fatal(0, manifestfile);
    return 0;
}
