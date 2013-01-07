#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include "rpki-asn1/certificate.h"
#include "util/cryptlib_compat.h"
#include <rpki-object/keyfile.h>
#include <casn/casn.h>
#include <casn/asn.h>
#include <util/hashutils.h>
#include <time.h>

#define SHA1_HASH_LENGTH 20
#define SHA2_HASH_LENGTH 32

static int writeHashedPublicKey(
    struct casn *keyp)
{
    uchar *bitval;
    int siz = readvsize_casn(keyp, &bitval);
    uchar *hashbuf = calloc(SHA1_HASH_LENGTH, sizeof(uchar));
    siz = gen_hash(&bitval[1], siz - 1, hashbuf, CRYPT_ALGO_SHA);
    free(bitval);

    // write out the hashed key
    int i = 0;
    printf("0x");
    for (i = 0; i < SHA1_HASH_LENGTH; i++)
        printf("%02X", (unsigned int)hashbuf[i]);
    free(hashbuf);
    return siz;
}

static int writeFileHash(
    char *buf,
    int len)
{
    uchar *hashbuf = calloc(SHA2_HASH_LENGTH, sizeof(uchar));
    int siz;
    siz = gen_hash((uchar *) buf, len, hashbuf, CRYPT_ALGO_SHA2);

    // write out the hashed key
    int i = 0;
    printf("0x");
    for (i = 0; i < SHA2_HASH_LENGTH; i++)
        printf("%02X", (unsigned int)hashbuf[i]);

    free(hashbuf);
    return siz;
}


// print usage to stdout for the user
void printUsage(
    char **argv)
{
    fprintf(stdout, "Usage:\n");
    fprintf(stdout, "        %s -f filename.p15\n", argv[0]);
    fprintf(stdout, "\n");
    fprintf(stdout,
            "where filename.p15 containts a public/private key pair\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "options: -h print this usage\n");
    exit(0);
}


int main(
    int argc,
    char *argv[])
{
    int c;
    char *configFile = NULL;
    char *name = NULL;


    // parse options
    while ((c = getopt(argc, argv, "f:n:")) != -1)
    {
        switch (c)
        {
        case 'f':
            configFile = optarg;
            break;
        case 'n':
            name = optarg;
            break;
        case '?':
            printUsage(argv);
            break;

        default:
            fprintf(stderr, "Illegal Option\n");
            printUsage(argv);
            break;
        }
    }

    if (configFile == NULL && name == NULL)
    {
        printUsage(argv);
        return -1;
    }
    else if (configFile != NULL && name != NULL)
    {
        printUsage(argv);
        return -1;
    }

    if (configFile != NULL)
    {
        struct Certificate certp;
        Certificate(&certp, (unsigned short)0);
        struct CertificateToBeSigned *ctftbsp = &certp.toBeSigned;
        struct SubjectPublicKeyInfo *spkinfop = &ctftbsp->subjectPublicKeyInfo;
        struct casn *spkp = &spkinfop->subjectPublicKey;

        if (!fillPublicKey(spkp, configFile))
            return -1;
        writeHashedPublicKey(spkp);

        return 1;
    }
    else
    {
        struct stat stbuf;
        char *buf;
        int flen;

        if (stat(name, &stbuf) != 0)
        {
            fprintf(stderr, "Error getting file size %s\n", name);
            return 1;
        }

        flen = stbuf.st_size;
        if ((buf = calloc(flen, sizeof(char))) == NULL)
        {
            fprintf(stderr, "Memory Error\n");
            return 1;
        }

        FILE *fp = fopen(name, "r");

        int size = fread(buf, sizeof(char), flen, fp);
        writeFileHash(buf, size);
        fclose(fp);
        free(buf);

        return 1;
    }

}
