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
#include <sys/stat.h>
#include <rpki-asn1/certificate.h>
#include <rpki-object/cms/cms.h>
#include <casn/casn.h>
#include "util/hashutils.h"
#include "util/logging.h"

#define MSG_OK "Finished OK"
#define MSG_GET "Couldn't get %s"
#define MSG_HASHING "Error hashing %s"

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
    if (argc < 4)
    {
        fprintf(stderr, "Usage: CMSfile EEkeyfile rehashFile(s)\n");
        return -1;
    }
    strcpy(keyring.label, "label");
    strcpy(keyring.password, "password");
    if (get_casn_file(&cms.self, argv[1], 0) < 0)
        FATAL(MSG_GET, "CMS file");
    char *c = strrchr(argv[1], (int)'.');
    if (!c || (strcmp(c, ".man") && strcmp(c, ".mft") && strcmp(c, ".mnf")))
        FATAL(MSG_GET, "CMSfile suffix");
    int i;
    char *fname;
    uchar hashbuf[40];
    uchar *tbh;
    int tbh_lth;
    struct Manifest *manp =
        &cms.content.signedData.encapContentInfo.eContent.manifest;
    for (fname = argv[i = 3]; fname; fname = argv[++i])
    {
        struct stat statbuf;
        struct FileAndHash *fahp;
        int j,
            fd;
        for (fahp = (struct FileAndHash *)member_casn(&manp->fileList.self, 0);
             fahp; fahp = (struct FileAndHash *)next_of(&fahp->self))
        {
            uchar *f;
            int fl = readvsize_casn(&fahp->file, &f);
            if (fl < 0)
                FATAL(MSG_HASHING, fname);
            if ((ssize_t)fl == (ssize_t)strlen(fname) && !strcmp((char *)f, fname))
                break;
        }
        if (!fahp || stat(fname, &statbuf) < 0 ||
            !(tbh = (uchar *) calloc(1, statbuf.st_size + 4)) ||
            (fd = open(fname, O_RDONLY)) < 0 ||
            (tbh_lth = read(fd, tbh, statbuf.st_size + 1)) < 0)
            FATAL(MSG_GET, fname);
        hashbuf[0] = 0;
        j = gen_hash(tbh, tbh_lth, &hashbuf[1], CRYPT_ALGO_SHA2);
        if (j < 0)
            FATAL(MSG_HASHING, fname);
        free(tbh);
        write_casn(&fahp->hash, hashbuf, j + 1);
    }
    const char *msg = signCMS(&cms, argv[2], 0);
    if (msg)
        fprintf(stderr, "%s\n", msg);
    else
        put_casn_file(&cms.self, argv[1], 0);
    return 0;
}
