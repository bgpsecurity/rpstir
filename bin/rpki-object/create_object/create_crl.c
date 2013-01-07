
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include "util/cryptlib_compat.h"
#include "rpki-object/crl.h"
#include "rpki-object/certificate.h"
#include "rpki-asn1/extensions.h"
#include <rpki-asn1/roa.h>
#include <rpki-asn1/keyfile.h>
#include <casn/casn.h>
#include <casn/asn.h>
#include <time.h>
#include "create_object.h"
#include "obj_err.h"

char *crl_template = TEMPLATES_DIR "/crl_template.crl";

/*
 * function declarations 
 */
extern int sign_cert(
    struct Certificate *certp,
    char *keyname);
extern int fieldInTable(
    char *field,
    int field_len,
    struct object_field *tbl);
int get_table_value(
    char *name,
    struct object_field *table,
    char **value,
    int *type);
int use_pcert(
    void *crl,
    void *val);                 // filename of parent cert
int write_crl_iname(
    void *crl,
    void *val);
int write_lastUpdate_time(
    void *crl,
    void *val);
int write_nextUpdate_time(
    void *crl,
    void *val);
int write_revoked_certlist(
    void *crl,
    void *val);
int write_crl_aki(
    void *cert,
    void *val);
int write_crlNum(
    void *cert,
    void *val);

/*
 * Note: Some fields are in the table as optional but are actually required.
 * These are special cases where we could get the value from multiple places.
 * For example, Issuer Name can come from the parentcertfile (subject in the
 * parentcertfile) or it can be specified exactly as issuer) 
 */
struct object_field crl_field_table[] = {
    {"outputfilename", TEXT, NULL, REQUIRED, NULL},
    {"parentcertfile", TEXT, NULL, OPTIONAL, use_pcert},
    {"parentkeyfile", TEXT, NULL, OPTIONAL, NULL},
    {"issuer", TEXT, NULL, OPTIONAL, write_crl_iname},
    {"thisupdate", TEXT, NULL, REQUIRED, write_lastUpdate_time},
    {"nextupdate", TEXT, NULL, REQUIRED, write_nextUpdate_time},
    {"crlnum", INTEGER, NULL, REQUIRED, write_crlNum},
    {"revokedcertlist", LIST, NULL, OPTIONAL, write_revoked_certlist},
    {"aki", OCTETSTRING, NULL, OPTIONAL, write_crl_aki},
    {"signatureValue", OCTETSTRING, NULL, OPTIONAL, NULL},
    {NULL, 0, NULL, REQUIRED, NULL}
};

struct object_field *get_crl_field_table(
    )
{
    return crl_field_table;
}


struct CRLExtension *findCrlExtension(
    struct CrlExtensions *extsp,
    char *oid)
{
    struct CRLExtension *extp;

    if (!num_items(&extsp->self))
        return (struct CRLExtension *)0;

    for (extp = (struct CRLExtension *)member_casn(&extsp->self, 0);
         extp && diff_objid(&extp->extnID, oid);
         extp = (struct CRLExtension *)next_of(&extp->self));
    return extp;
}


/*
 * Take values from the certificate and write them to the 
 * current CRL
 * val is filename of the parent certificate
 * fields of interest:
 *    signature algorithm ID - overwrite (from template)
 *    issuer     - overwrite using issuer cert's subject
 *    aki        - overwrite using issuer cert's ski
 *    algorithm ID  overwrite (from template)
 */
int use_pcert(
    void *crl,
    void *val)
{
    struct Certificate issuer;
    struct CertificateRevocationList *crlp =
        (struct CertificateRevocationList *)crl;
    struct CertificateRevocationListToBeSigned *crltbsp = &crlp->toBeSigned;
    Certificate(&issuer, (ushort) 0);
    struct Extension *iextp;
    struct CRLExtension *cextp;

    if (val == NULL)
        return SUCCESS;

    if (get_casn_file(&issuer.self, val, 0) < 0)
    {
        fprintf(stdout, "can't use issuers cert %s", (char *)val);
        return -1;
    }
    // copy algorithm identifiers (overwrite template value)
    copy_casn(&crlp->algorithm.self, &issuer.toBeSigned.signature.self);
    copy_casn(&crltbsp->signature.self, &issuer.toBeSigned.signature.self);

    // copy subject name from issuer cert into issuer name in cert if issuer
    // name
    // not filled in.
    copy_casn(&crltbsp->issuer.self, &issuer.toBeSigned.subject.self);

    // overwrite crl aki extension using ski from issuer's cert
    if (!(iextp = find_extension(&issuer.toBeSigned.extensions,
                                 id_subjectKeyIdentifier, false)))
    {
        fprintf(stderr, "Error: could not obtain SKI from issuer cert");
        return -1;
    }
    cextp = findCrlExtension(&crltbsp->extensions, id_authKeyId);
    if (!cextp)
    {
        cextp =
            (struct CRLExtension *)inject_casn(&crltbsp->extensions.self, 0);
        write_objid(&cextp->extnID, id_authKeyId);
    }
    copy_casn(&cextp->extnValue.authKeyId.keyIdentifier,
              &iextp->extnValue.subjectKeyIdentifier);

    return (SUCCESS);
}

int write_revoked_entry(
    struct CertificateRevocationListToBeSigned *crltbsp,
    char *entry,
    int entry_len,
    int num)
{
    struct CRLEntry *crlentryp;
    char *str_num;
    char *eptr;
    char *rtime;
    int rtime_len,
        snum_len;
    long certnum;
    int utclen = 13;
    int glen = 15;

    // we have a % separated pair of serial number and date to add
    eptr = entry + entry_len;
    rtime = strchr(entry, '%');
    if (rtime != NULL)
    {
        crlentryp =
            (struct CRLEntry *)inject_casn(&crltbsp->revokedCertificates.self,
                                           num);
        if (!crlentryp)
            return -1;

        // pull out the serial number and convert to an int
        snum_len = rtime - entry;
        if ((str_num = calloc(snum_len, sizeof(char))) == NULL)
            return -1;
        memcpy(str_num, entry, snum_len);
        certnum = atoi(str_num);
        free(str_num);
        write_casn_num(&crlentryp->userCertificate, (long)certnum);

        // write out the time
        rtime++;
        rtime_len = eptr - rtime;
        if (rtime_len == utclen)
            write_casn(&crlentryp->revocationDate.utcTime,
                       (uchar *) rtime, rtime_len);
        else if (rtime_len == glen)
            write_casn(&crlentryp->revocationDate.generalTime,
                       (uchar *) rtime, rtime_len);
    }
    return SUCCESS;
}



/*
 * parse comma separated list of serialnum%date values
 */
int write_revoked_certlist(
    void *crl,
    void *val)
{
    int numcerts = 0;
    char *ptr = val,
        *next;
    int ptr_len;
    char token = ',';
    struct CertificateRevocationList *crlp = crl;
    struct CertificateRevocationListToBeSigned *crltbsp = &crlp->toBeSigned;

    while (ptr != NULL)
    {
        next = strchr(ptr, token);
        while (isspace((int)(unsigned char)*ptr))
            ptr++;              // strip leading spaces
        if (next == NULL)
            ptr_len = strlen(ptr);
        else
        {
            ptr_len = (char *)next - (char *)ptr;
            next++;             // jump over the comma
        }

        if (write_revoked_entry(crltbsp, ptr, ptr_len, numcerts) == SUCCESS)
            numcerts++;
        ptr = next;
    }
    return SUCCESS;
}

/*
 * Write the crl number into the CRL
 * crlnumber is an extension
 */
int write_crlNum(
    void *crl,
    void *val)
{
    int cnum;
    struct CertificateRevocationList *crlp =
        (struct CertificateRevocationList *)crl;
    struct CertificateRevocationListToBeSigned *crltbsp = &crlp->toBeSigned;
    struct CRLExtension *extp;

    cnum = atoi(val);
    // fprintf(stdout, "Writing CRL Number %d to CRL\n",cnum);

    if (!(extp = findCrlExtension(&crltbsp->extensions, id_cRLNumber)))
        extp =
            (struct CRLExtension *)inject_casn(&crltbsp->extensions.self, 0);
    else
        clear_casn(&extp->self);
    write_objid(&extp->extnID, id_cRLNumber);
    if (write_casn_num(&extp->extnValue.cRLNumber, cnum) <= 0)
        return -1;

    return SUCCESS;
}

/*
 * Write common name into name of cert
 */
int add_crl_cn(
    struct RelativeDistinguishedName *rdnp,
    char *namep,
    int len)
{

    struct AttributeValueAssertion *avap =
        (struct AttributeValueAssertion *)inject_casn(&rdnp->self, 0);

    if ((write_objid(&avap->objid, id_commonName) > 0) &&
        (write_casn(&avap->value.commonName.self, (uchar *) namep, len) > 0))
        return SUCCESS;

    return -1;
}

/*
 * Write serial number into name
 */
int add_crl_sn(
    struct RelativeDistinguishedName *rdnp,
    char *namep,
    int len)
{

    struct AttributeValueAssertion *avap =
        (struct AttributeValueAssertion *)inject_casn(&rdnp->self, 0);

    if ((write_objid(&avap->objid, id_serialNumber) > 0) &&
        (write_casn(&avap->value.serialNumber, (uchar *) namep, len) > 0))
        return SUCCESS;

    return -1;
}

/*
 * Write the issuer name to the CRL
 * The value is the issuer name as a printable string.
 * It can be the commonName%SerialNumber.If the % is in the
 * string the the first half is commonName and the second half is
 * the serialNum. i.e. val= "Gollum" or val="Bilbo Baggins%135AXZ79"
 */
int write_crl_iname(
    void *crl,
    void *val)
{

    struct CertificateRevocationList *crlp =
        (struct CertificateRevocationList *)crl;
    struct CertificateRevocationListToBeSigned *crltbsp = &crlp->toBeSigned;
    char token = '%';
    char *sn = NULL;
    int len;
    struct RDNSequence *rdnsp;
    struct RelativeDistinguishedName *rdnp;

    clear_casn(&crltbsp->issuer.self);
    sn = strchr(val, token);

    rdnsp = (struct RDNSequence *)&crltbsp->issuer.rDNSequence;

    rdnp = (struct RelativeDistinguishedName *)inject_casn(&rdnsp->self, 0);
    if (rdnp == NULL)
        return -1;

    if (sn != NULL)
    {
        len = (char *)sn - (char *)val;
        sn++;
        if ((add_crl_cn(rdnp, (char *)val, len) == 0) &&
            (add_crl_sn(rdnp, (char *)sn, strlen(sn)) == 0))
            return (SUCCESS);
    }
    else
    {
        if (add_crl_cn(rdnp, val, strlen(val)) == 0)
            return SUCCESS;
    }
    return -1;
}

/*
 * Write out the notBefore validity date
 */
int write_lastUpdate_time(
    void *crl,
    void *val)
{
    struct CertificateRevocationList *crlp =
        (struct CertificateRevocationList *)crl;
    struct CertificateRevocationListToBeSigned *crltbsp = &crlp->toBeSigned;
    int len,
        ret;
    int utclen = 13;
    int glen = 15;

    if (val == NULL)
        return -1;

    clear_casn(&crltbsp->lastUpdate.self);

    len = strlen(val);
    if (len == utclen)
        ret = write_casn(&crltbsp->lastUpdate.utcTime,
                         (uchar *) val, strlen(val));
    else if (len == glen)
        ret =
            write_casn(&crltbsp->lastUpdate.generalTime, (uchar *) val,
                       strlen(val));
    else
        ret = -1;

    if (ret > 0)
        return (SUCCESS);

    return -1;
}

/*
 *
 */
int write_nextUpdate_time(
    void *crl,
    void *val)
{
    struct CertificateRevocationList *crlp =
        (struct CertificateRevocationList *)crl;
    struct CertificateRevocationListToBeSigned *crltbsp = &crlp->toBeSigned;
    int len,
        ret;
    int utclen = 13;
    int glen = 15;


    if (val == NULL)
        return -1;

    clear_casn(&crltbsp->nextUpdate.self);

    // fprintf(stdout, "Next Update is %s\n", (char *)val);
    len = strlen(val);

    if (len == utclen)
        ret =
            write_casn(&crltbsp->nextUpdate.utcTime, (uchar *) val,
                       strlen(val));
    else if (len == glen)
        ret =
            write_casn(&crltbsp->nextUpdate.generalTime, (uchar *) val,
                       strlen(val));
    else
        ret = -1;

    if (ret > 0)
        return (SUCCESS);

    return -1;
}

int write_crl_sig(
    struct CertificateRevocationList *crlp,
    char *val)
{
    struct CertificateRevocationListToBeSigned *crltbsp = &crlp->toBeSigned;
    int str_len,
        sig_len;
    char *str_sig = val;
    unsigned char *sig = NULL;
    int bytes_written;

    if (val == NULL)
        return -1;

    // strip off leading spaces and the 0x
    while (isspace((int)(unsigned char)*str_sig))
        str_sig++;
    if (strncmp(str_sig, "0x", 2) != 0)
        return -1;

    str_sig += 2;
    str_len = strlen(str_sig);
    sig_len = (str_len + 1) / 2;

    sig = calloc(sig_len, sizeof(char));
    if ((bytes_written = read_hex_val(str_sig, str_len, sig)) <= 0)
    {
        fprintf(stdout, "error converting signature (%s)\n", (char *)val);
        free(sig);
        return -1;
    }

    if (write_casn(&crlp->signature, sig, bytes_written) < 0)
    {
        free(sig);
        return -1;
    }

    free(sig);
    write_objid(&crltbsp->signature.algorithm, id_sha_256WithRSAEncryption);
    write_casn(&crltbsp->signature.parameters.rsadsi_SHA256_WithRSAEncryption,
               (uchar *) "", 0);
    write_objid(&crlp->algorithm.algorithm, id_sha_256WithRSAEncryption);
    write_casn(&crlp->algorithm.parameters.rsadsi_SHA256_WithRSAEncryption,
               (uchar *) "", 0);
    return SUCCESS;
}

int write_key_id(
    struct CertificateRevocationList *crlp,
    char *id,
    char *val)
{
    struct CertificateRevocationListToBeSigned *crltbsp = &crlp->toBeSigned;
    int str_len,
        ki_len;
    char *str_ki = val;
    unsigned char *ki = NULL;
    int bytes_written;
    struct CRLExtension *extp;
    int ret;

    // strip off leading spaces and the 0x
    while (isspace((int)(unsigned char)*str_ki))
        str_ki++;
    if (strncmp(str_ki, "0x", 2) != 0)
        return -1;
    str_ki += 2;

    str_len = strlen(str_ki);

    ki_len = (str_len + 1) / 2;

    ki = calloc(ki_len, sizeof(char));
    if ((bytes_written = read_hex_val(str_ki, str_len, ki)) <= 0)
    {
        fprintf(stdout, "error converting key identifier (%s)\n", (char *)val);
        return -1;
    }

    // if it is there, clear it first
    if (!(extp = findCrlExtension(&crltbsp->extensions, id_authKeyId)))
        extp =
            (struct CRLExtension *)inject_casn(&crltbsp->extensions.self, 0);
    else
        clear_casn(&extp->self);

    write_objid(&extp->extnID, id);
    ret =
        write_casn(&extp->extnValue.authKeyId.keyIdentifier, ki,
                   bytes_written);
    free(ki);

    if (ret > 0)
        return SUCCESS;

    return -1;
}

/*
 * write crl aki
 */
int write_crl_aki(
    void *crl,
    void *val)
{
    return (write_key_id(crl, id_authKeyId, val));
}

/*
 * Create a Certificate Revocation List
 */
int create_crl(
    struct object_field *table)
{
    int i;
    struct CertificateRevocationList crl;
    CertificateRevocationList(&crl, (ushort) 0);
    char *keyfile = NULL,
        *val;
    int val_type;

    if (!templateFile)
    {
        templateFile = crl_template;
    }

    // Read the crl template into the certifcate
    if (get_casn_file(&crl.self, (char *)templateFile, 0) < 0)
    {
        warn(FILE_OPEN_ERR, (char *)templateFile);
        return (FILE_OPEN_ERR);
    }

    // Populate the crl fields with data from the 
    // table. Note the table is populated from input arguments
    // If there is no function to call and the argument is optional then
    // it is ok otherwise it is an error.
    for (i = 0; table[i].name != NULL; i++)
    {
        if (table[i].func != NULL)
        {
            if (table[i].value != NULL)
            {
                if (table[i].func(&crl.self, table[i].value) < 0)
                {
                    fprintf(stderr, "Error writing %s into field %s\n",
                            table[i].value, table[i].name);
                }
            }
            else
            {
                if (table[i].required)
                    fprintf(stderr, "Missing value for %s\n", table[i].name);
            }
        }
    }

    // if signature value is set in the table, write that value as the
    // signature,
    // otherwise sign it
    if (get_table_value("signatureValue", table, &val, &val_type) != 0)
    {
        fprintf(stdout, "Error writing signature");
        return (-1);
    }

    if (val != NULL)            // input signature
    {
        if (write_crl_sig(&crl, val) != SUCCESS)
        {
            fprintf(stdout, "Error writing signature");
            return (-1);
        }
    }
    else
    {
        get_table_value("parentkeyfile", table, &keyfile, &val_type);

        if (keyfile == NULL)
            return -1;

        const char * msg = signCRL(&crl, keyfile);
        if (msg != NULL)
        {
            fprintf(stderr, "Error signing CRL: %s\n", msg);
            return -1;
        }
    }

    // write out the certificate using the ouput filename
    if (get_table_value("outputfilename", table, &val, &val_type) < 0)
    {
        warn(FILE_WRITE_ERR, "outputfilename missing");
        return (FILE_WRITE_ERR);
    }
    if (put_casn_file(&crl.self, val, 0) < 0)
    {
        warn(FILE_WRITE_ERR, val);
        return (FILE_WRITE_ERR);
    }
    else
        warn(SUCCESS, val);

    return (SUCCESS);

}
