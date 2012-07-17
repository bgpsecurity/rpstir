/*
 * $Id: make_manifest.c 453 2007-07-25 15:30:40Z gardiner $ 
 */


#include "rpki-object/cms/cms.h"
#include "rpki-asn1/manifest.h"
#include "util/cryptlib_compat.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

/*
 * This file has a program to make manifests. 
 */

char *msgs[] = {
    "Finished OK\n",
    "Couldn't open %s\n",       // 1
    "Error reading %s\n",
    "Error adding %s\n",        // 3
    "Error inserting %s\n",
    "Error in %s creating signature\n", // 5
    "Error writing %s\n",
    "File name %s too long\n",  // 7
};

#define CURR_FILE_SIZE 512

static int fatal(
    int msg,
    char *paramp);
static int gen_sha2(
    uchar * inbufp,
    int bsize,
    uchar * outbufp);

static int add_name(
    char *curr_file,
    struct Manifest *manp,
    int num)
{
    int fd,
        siz,
        hsiz;
    uchar *b,
        hash[40];
    struct FileAndHash *fahp;
    if ((fd = open(curr_file, O_RDONLY)) < 0)
        fatal(1, curr_file);
    siz = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, 0);
    b = (uchar *) calloc(1, siz);
    if (read(fd, b, siz + 2) != siz)
        fatal(2, curr_file);
    hsiz = gen_sha2(b, siz, hash);
    if (inject_casn(&manp->fileList.self, num) < 0)
        fatal(3, "fileList");
    fahp = (struct FileAndHash *)member_casn(&manp->fileList.self, num);
    write_casn(&fahp->file, (uchar *) curr_file, strlen(curr_file));
    write_casn_bits(&fahp->hash, hash, hsiz, 0);
    return 1;
}

static int add_names(
    char *curr_file,
    char *c,
    struct Manifest *manp,
    int num)
{
    FILE *str;
    char *a;
    if (!(str = fopen(&c[1], "r")))
        fatal(1, &c[1]);
    while ((fgets(c, (CURR_FILE_SIZE - (c - curr_file)), str)))
    {
        if (strlen(curr_file) >= CURR_FILE_SIZE - 1)
            fatal(7, c);
        for (a = c; *a > ' '; a++);
        *a = 0;
        if (*c == '-')
            num = add_names(curr_file, c, manp, num);
        else
            num += add_name(curr_file, manp, num);
    }
    fclose(str);
    return num;
}

static int gen_sha2(
    uchar * inbufp,
    int bsize,
    uchar * outbufp)
{
    CRYPT_CONTEXT hashContext;
    uchar hash[40];
    int ansr;

    memset(hash, 0, 40);
    cryptInit();
    cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2);
    cryptEncrypt(hashContext, inbufp, bsize);
    cryptEncrypt(hashContext, inbufp, 0);
    cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ansr);
    cryptDestroyContext(hashContext);
    cryptEnd();
    memcpy(outbufp, hash, ansr);
    return ansr;
}

static int fatal(
    int msg,
    char *paramp)
{
    fprintf(stderr, msgs[msg], paramp);
    exit(msg);
}

static void getDate(
    struct casn *casnp,
    char *text)
{
    char locbuf[20];
    printf("%supdate date (YYYYMMDDhhmssZ)? ", text);
    while (1)
    {
        fgets(locbuf, sizeof(locbuf), stdin);
        char *c;
        for (c = locbuf; *c > ' '; c++);
        *c = 0;
        if (write_casn(casnp, (uchar *) locbuf, strlen(locbuf)) > 0)
            return;
        printf("Invalid date.  Try again ");
    }
}

int main(
    int argc,
    char **argv)
{
    char *c,
        curr_file[CURR_FILE_SIZE],
        locbuf[20];
    struct ROA roa;
    struct AlgorithmIdentifier *algidp;
    int man_num;

    if (argc < 4)
    {
        printf
            ("Args needed: output file, certificate file, key file, optional directory\n");
        return 0;
    }
    ROA(&roa, 0);
    write_objid(&roa.contentType, id_signedData);
    write_casn_num(&roa.content.signedData.version.self, (long)3);
    inject_casn(&roa.content.signedData.digestAlgorithms.self, 0);
    algidp =
        (struct AlgorithmIdentifier *)member_casn(&roa.content.
                                                  signedData.digestAlgorithms.
                                                  self, 0);
    write_objid(&algidp->algorithm, id_sha256);
    write_casn(&algidp->parameters.sha256, (uchar *) "", 0);
    write_objid(&roa.content.signedData.encapContentInfo.eContentType,
                id_roa_pki_manifest);
    struct Manifest *manp =
        &roa.content.signedData.encapContentInfo.eContent.manifest;
    printf("What manifest number? ");
    fgets(locbuf, sizeof(locbuf), stdin);
    sscanf(locbuf, "%d", &man_num);
    write_casn_num(&manp->manifestNumber, (long)man_num);
    getDate(&manp->thisUpdate, "This");
    getDate(&manp->nextUpdate, "Next");
    write_objid(&manp->fileHashAlg, id_sha256);

    // now get the files 
    memset(curr_file, 0, CURR_FILE_SIZE);
    if (argc > 4)
    {
        if (strlen(argv[4]) > CURR_FILE_SIZE - 8)
            fatal(7, argv[4]);
        strcpy(curr_file, argv[4]);
        for (c = curr_file; *c > ' '; c++);
        if (c > curr_file && c[-1] != '/')
            *c++ = '/';
    }
    else
        c = curr_file;
    int num;
    printf("Now give the names of the files to go in the manifest\n");
    printf("Terminate with a null name\n");
    printf
        ("If a name begins with '-', the remainder of the name is considered\n");
    printf("to be the full path to a file containing a list of file names.\n");
    for (num = 0; 1;)
    {
        char *a;

        printf("File[%d]? ", num);
        fgets(c, (CURR_FILE_SIZE - (c - curr_file)), stdin);
        if (strlen(curr_file) > CURR_FILE_SIZE - 1)
            fatal(7, curr_file);
        if (*c < ' ')
            break;
        for (a = c; *a > ' '; a++);
        *a = 0;                 // remove carriage return
        if (*c != '-')
            num += add_name(curr_file, manp, num);
        else
            num = add_names(curr_file, c, manp, num);
    }
    if (!inject_casn(&roa.content.signedData.certificates.self, 0))
        fatal(4, "signedData");
    struct Certificate *certp =
        (struct Certificate *)member_casn(&roa.content.signedData.certificates.
                                          self, 0);
    if (get_casn_file(&certp->self, argv[2], 0) < 0)
        fatal(2, argv[2]);
    if (!inject_casn(&roa.content.signedData.signerInfos.self, 0))
        fatal(4, "signerInfo");
    struct SignerInfo *sigInfop =
        (struct SignerInfo *)member_casn(&roa.content.signedData.signerInfos.
                                         self, 0);
    write_casn_num(&sigInfop->version.v3, 3);
    write_objid(&sigInfop->digestAlgorithm.algorithm, id_sha256);
    write_objid(&sigInfop->signatureAlgorithm.algorithm,
                id_sha_256WithRSAEncryption);

    if ((c = signCMS(&roa, argv[3], 0)))
        fatal(5, c);
    if (put_casn_file(&roa.self, argv[1], 0) < 0)
        fatal(6, argv[1]);
    printf("What readable file, if any? ");
    fgets(curr_file, CURR_FILE_SIZE, stdin);
    curr_file[strlen(curr_file) - 1] = 0;
    if (*curr_file > ' ')
    {
        int dsize = dump_size(&roa.self);
        c = (char *)calloc(1, dsize + 2);
        dump_casn(&roa.self, c);
        FILE *str = fopen(curr_file, "w");
        fprintf(str, "%s", c);
        fclose(str);
    }
    fatal(0, "");
    return 0;
}
