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
#include "util/logging.h"

/*
 * This file has a program to make manifests. 
 */

#define MSG_OK "Finished OK"
#define MSG_OPEN "Couldn't open %s"
#define MSG_READING "Error reading %s"
#define MSG_ADDING "Error adding %s"
#define MSG_INSERTING "Error inserting %s"
#define MSG_CREATING_SIG "Error in %s creating signature"
#define MSG_WRITING "Error writing %s"
#define MSG_FN_LONG "File name %s too long"
#define MSG_ERROR "Error %s"

#define CURR_FILE_SIZE 512

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
        FATAL(MSG_OPEN, curr_file);
    siz = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, 0);
    b = (uchar *) calloc(1, siz);
    if (read(fd, b, siz + 2) != siz)
        FATAL(MSG_READING, curr_file);
    hsiz = gen_sha2(b, siz, hash);
    fahp = (struct FileAndHash *)inject_casn(&manp->fileList.self, num);
    if (fahp == NULL)
        FATAL(MSG_ADDING, "fileList");
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
        FATAL(MSG_OPEN, &c[1]);
    while ((fgets(c, (CURR_FILE_SIZE - (c - curr_file)), str)))
    {
        if (strlen(curr_file) >= CURR_FILE_SIZE - 1)
            FATAL(MSG_FN_LONG, c);
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
    if (cryptInit() != CRYPT_OK)
    {
        FATAL(MSG_ERROR, "initializing cryptlib");
    }
    if (cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2) != CRYPT_OK)
    {
        FATAL(MSG_ERROR, "creating cryptlib hash context");
    }
    cryptEncrypt(hashContext, inbufp, bsize);
    cryptEncrypt(hashContext, inbufp, 0);
    cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ansr);
    cryptDestroyContext(hashContext);
    cryptEnd();
    memcpy(outbufp, hash, ansr);
    return ansr;
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
    struct CMS cms;
    struct AlgorithmIdentifier *algidp;
    int man_num;

    if (argc < 4)
    {
        printf
            ("Args needed: output file, certificate file, key file, optional directory\n");
        return 0;
    }
    CMS(&cms, 0);
    write_objid(&cms.contentType, id_signedData);
    write_casn_num(&cms.content.signedData.version.self, (long)3);
    inject_casn(&cms.content.signedData.digestAlgorithms.self, 0);
    algidp =
        (struct AlgorithmIdentifier *)member_casn(&cms.content.
                                                  signedData.digestAlgorithms.
                                                  self, 0);
    write_objid(&algidp->algorithm, id_sha256);
    write_casn(&algidp->parameters.sha256, (uchar *) "", 0);
    write_objid(&cms.content.signedData.encapContentInfo.eContentType,
                id_roa_pki_manifest);
    struct Manifest *manp =
        &cms.content.signedData.encapContentInfo.eContent.manifest;
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
            FATAL(MSG_FN_LONG, argv[4]);
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
            FATAL(MSG_FN_LONG, curr_file);
        if (*c < ' ')
            break;
        for (a = c; *a > ' '; a++);
        *a = 0;                 // remove carriage return
        if (*c != '-')
            num += add_name(curr_file, manp, num);
        else
            num = add_names(curr_file, c, manp, num);
    }
    if (!inject_casn(&cms.content.signedData.certificates.self, 0))
        FATAL(MSG_INSERTING, "signedData");
    struct Certificate *certp =
        (struct Certificate *)member_casn(&cms.content.signedData.certificates.
                                          self, 0);
    if (get_casn_file(&certp->self, argv[2], 0) < 0)
        FATAL(MSG_READING, argv[2]);
    if (!inject_casn(&cms.content.signedData.signerInfos.self, 0))
        FATAL(MSG_INSERTING, "signerInfo");
    struct SignerInfo *sigInfop =
        (struct SignerInfo *)member_casn(&cms.content.signedData.signerInfos.
                                         self, 0);
    write_casn_num(&sigInfop->version.v3, 3);
    write_objid(&sigInfop->digestAlgorithm.algorithm, id_sha256);
    write_objid(&sigInfop->signatureAlgorithm.algorithm,
                id_rsadsi_rsaEncryption);

    const char *msg;
    if ((msg = signCMS(&cms, argv[3], 0)))
        FATAL(MSG_CREATING_SIG, msg);
    if (put_casn_file(&cms.self, argv[1], 0) < 0)
        FATAL(MSG_WRITING, argv[1]);
    printf("What readable file, if any? ");
    fgets(curr_file, CURR_FILE_SIZE, stdin);
    curr_file[strlen(curr_file) - 1] = 0;
    if (*curr_file > ' ')
    {
        int dsize = dump_size(&cms.self);
        c = (char *)calloc(1, dsize + 2);
        dump_casn(&cms.self, c);
        FILE *str = fopen(curr_file, "w");
        fprintf(str, "%s", c);
        fclose(str);
    }
    DONE(MSG_OK);
    return 0;
}
