/*
 * $Id: make_crl.c 453 2008-05-28 15:30:40Z cgardiner $ 
 */


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include "rpki-object/crl.h"
#include "rpki-object/certificate.h"
#include "rpki-asn1/extensions.h"
#include <util/cryptlib_compat.h>
#include <rpki-asn1/roa.h>

char *msgs[] = {
    "Finished %s OK\n",
    "Usage: CRLfile startdelta enddelta\n",
    "Can't get %s\n",           // 2
    "Invalid CRL number %s\n",
    "Error signing CRL\n",      // 4
    "Error %s\n",
    "Error writing CRL to %s\n",        // 6
    "Invalid time delta %s\n",
};

static int fatal(
    int err,
    char *param)
{
    fprintf(stderr, msgs[err], param);
    exit(err);
}

static long getCertNum(
    char *certfile)
{
    char *c;
    for (c = certfile; *c && *c != '.'; c++);
    if (!*c)
        strcpy(c, ".cer");
    struct Certificate cert;
    Certificate(&cert, (ushort) 0);
    if (get_casn_file(&cert.self, certfile, 0) < 0)
        fatal(2, certfile);
    long num;
    read_casn_num(&cert.toBeSigned.serialNumber, &num);
    delete_casn(&cert.self);
    return num;
}

static void make_fullpath(
    char *fullpath,
    char *locpath)
{
    // CRL goes in issuer's directory, e.g.
    // L1.crl goes nowhere else, 
    // L11.crl goes into C1/, 
    // L121.crl goes into C1/2 
    // L1231.crl goes into C1/2/3
    char *f = fullpath,
        *l = locpath;
    if (strlen(locpath) > 6)
    {
        *f++ = 'C';
        *l++;
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
            }
        }
    }
    strcpy(f, locpath);
}

int main(
    int argc,
    char **argv)
{
    if (argc < 4)
        fatal(1, (char *)0);
    struct stat tstat;
    fstat(0, &tstat);
    int filein = (tstat.st_mode & S_IFREG);
    char certname[40],
        crlname[40],
        keyfile[40];
    memset(certname, 0, 40);
    memset(crlname, 0, 40);
    char *c;
    strcpy(crlname, argv[1]);
    for (c = crlname; *c && *c != '.'; c++);
    int crlnum;
    if (sscanf(&c[-1], "%d", &crlnum) != 1)
        fatal(3, &c[-1]);
    if (!*c)
        strcpy(c, ".crl");
    strcpy(certname, argv[1]);
    certname[0] = 'C';
    for (c = certname; *c && *c != '.'; c++);
    strcpy(--c, ".cer");
    strcpy(keyfile, certname);
    for (c = keyfile; *c && *c != '.'; c++);
    strcpy(c, ".p15");

    const char *msg;

    struct CertificateRevocationList crl;
    struct Certificate cert;

    CertificateRevocationList(&crl, (ushort) 0);
    Certificate(&cert, (ushort) 0);
    if (get_casn_file(&cert.self, certname, 0) < 0)
        fatal(2, certname);
    struct CertificateRevocationListToBeSigned *crltbsp = &crl.toBeSigned;
    struct CertificateToBeSigned *ctbsp = &cert.toBeSigned;
    write_casn_num(&crltbsp->version.self, 1);
    copy_casn(&crltbsp->signature.self, &ctbsp->signature.self);
    copy_casn(&crl.algorithm.self, &ctbsp->signature.self);
    copy_casn(&crltbsp->issuer.self, &ctbsp->subject.self);

    time_t now = time((time_t) 0);
    clear_casn(&crltbsp->lastUpdate.self);
    clear_casn(&crltbsp->nextUpdate.self);
    if (adjustTime(&crltbsp->lastUpdate.utcTime, now, argv[2]))
        fatal(7, argv[2]);
    if (adjustTime(&crltbsp->nextUpdate.utcTime, now, argv[3]))
        fatal(7, argv[3]);

    struct Extension *iextp;
    struct CRLExtension *extp;
    int numext = 0;
    extp =
        (struct CRLExtension *)inject_casn(&crltbsp->extensions.self,
                                           numext++);
    write_objid(&extp->extnID, id_cRLNumber);
    write_casn_num(&extp->extnValue.cRLNumber, crlnum);
    extp =
        (struct CRLExtension *)inject_casn(&crltbsp->extensions.self,
                                           numext++);
    iextp = find_extension(&ctbsp->extensions, id_subjectKeyIdentifier, false);
    write_objid(&extp->extnID, id_authKeyId);
    copy_casn(&extp->extnValue.authKeyId.keyIdentifier,
              &iextp->extnValue.subjectKeyIdentifier);
    // now get the revocation info
    int numcerts;
    char certbuf[40];
    struct CRLEntry *crlentryp;
    if (!filein)
    {
        fprintf(stdout, "List certificates.  Format is:\n");
        fprintf(stdout, "Certfile mm/dd/yy\n");
    }
    for (numcerts = 0; fgets(certbuf, 40, stdin) && certbuf[0] > ' ';)
    {
        long certnum;
        char subjfile[80],
            delta[20];
        sscanf(certbuf, "%s %s\n", subjfile, delta);

        certnum = getCertNum(subjfile);
        crlentryp =
            (struct CRLEntry *)inject_casn(&crltbsp->revokedCertificates.self,
                                           numcerts++);
        int64_t longtime;
        write_casn_num(&crlentryp->userCertificate, (long)certnum);
        read_casn_time(&crltbsp->lastUpdate.utcTime, &longtime);
        now = longtime;
        adjustTime(&crlentryp->revocationDate.utcTime, now, delta);
    }
    msg = signCRL(&crl, keyfile);
    if (msg != NULL)
    {
        fatal(5, msg);
    }
    char fullpath[40];
    make_fullpath(fullpath, crlname);
    if (put_casn_file(&crl.self, crlname, 0) < 0)
        fatal(6, crlname);
    if (put_casn_file(&crl.self, fullpath, 0) < 0)
        fatal(2, fullpath);
    int siz = dump_size(&crl.self);
    char *rawp = (char *)calloc(1, siz + 4);
    siz = dump_casn(&crl.self, rawp);
    for (c = crlname; *c && *c != '.'; c++);
    strcpy(c, ".raw");
    int fd = open(crlname, (O_WRONLY | O_CREAT | O_TRUNC), (S_IRWXU));
    if (fd < 0)
        fatal(6, crlname);
    if (write(fd, rawp, siz) < 0)
        perror(crlname);
    close(fd);
    free(rawp);
    fatal(0, crlname);
    return 0;
}
