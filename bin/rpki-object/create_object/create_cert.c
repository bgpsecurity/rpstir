
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include "util/cryptlib_compat.h"
#include "rpki-object/certificate.h"
#include <rpki-asn1/roa.h>
#include <rpki-object/keyfile.h>
#include <casn/casn.h>
#include <casn/asn.h>
#include <util/hashutils.h>
#include <time.h>
#include "create_object.h"
#include "obj_err.h"
#include <string.h>

char *cacert_template = TEMPLATES_DIR "/ca_template.cer";
char *eecert_template = TEMPLATES_DIR "/ee_template.cer";
int eecert = 0;                 // either EE or CA
int selfSigned = 0;             // defaults to not self signed

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
int use_parent_cert(
    void *cert,
    void *val);                 // filename of parent cert
int use_parent_keyfile(
    void *cert,
    void *val);                 // filename of parent keyfile
int use_subject_keyfile(
    void *cert,
    void *val);                 // filename of subject keyfile
int write_serialNum(
    void *cert,
    void *val);
int write_issuer_name(
    void *cert,
    void *val);
int write_subject_name(
    void *cert,
    void *val);
int write_notBefore_time(
    void *cert,
    void *val);
int write_notAfter_time(
    void *cert,
    void *val);
int write_cert_pubkey(
    void *cert,
    void *val);
int write_cert_ski(
    void *cert,
    void *val);
int write_cert_aki(
    void *cert,
    void *val);
int write_cert_crldp(
    void *cert,
    void *val);
int write_cert_sia(
    void *cert,
    void *val);
int write_cert_aia(
    void *cert,
    void *val);
int write_cert_ipv4(
    void *cert,
    void *val);
int write_cert_ipv6(
    void *cert,
    void *val);
int write_cert_asnums(
    void *cert,
    void *val);

/*
 * Note: Some fields are in the table as optional but are actually required.
 * These are special cases where we could get the value from multiple places.
 * For example, Issuer Name can come from the parentcertfile (subject in the
 * parentcertfile) or it can be specified exactly as issuer) 
 */
struct object_field cert_field_table[] = {
    {"outputfilename", TEXT, NULL, REQUIRED, NULL},     // for the certificate
    {"parentcertfile", TEXT, NULL, OPTIONAL, use_parent_cert},
    {"parentkeyfile", TEXT, NULL, OPTIONAL, NULL},
    {"subjkeyfile", TEXT, NULL, OPTIONAL, use_subject_keyfile},
    {"type", TEXT, NULL, REQUIRED, NULL},       // either 'CA' or 'EE'
    {"serial", INTEGER, NULL, OPTIONAL, write_serialNum},       // serial
                                                                // number
    {"issuer", TEXT, NULL, OPTIONAL, write_issuer_name},        // issuers
                                                                // name
    {"subject", TEXT, NULL, OPTIONAL, write_subject_name},      // subject
                                                                // name
    {"notBefore", TEXT, NULL, REQUIRED, write_notBefore_time},  // validity
    {"notAfter", TEXT, NULL, REQUIRED, write_notAfter_time},    // validity
    {"pubkey", LIST, NULL, OPTIONAL, write_cert_pubkey},        // public Key
    {"ski", OCTETSTRING, NULL, OPTIONAL, write_cert_ski},       // Subj key
                                                                // identifier
    {"aki", OCTETSTRING, NULL, OPTIONAL, write_cert_aki},       // Issuer key
                                                                // id
    {"crldp", LIST, NULL, OPTIONAL, write_cert_crldp},  // crl distribution
                                                        // point
    {"aia", TEXT, NULL, OPTIONAL, write_cert_aia},      // auth information
                                                        // access 
    {"sia", TEXT, NULL, OPTIONAL, write_cert_sia},      // subj information
                                                        // access 
    {"ipv4", LIST, NULL, REQUIRED, write_cert_ipv4},    // ipv4 addresses
    {"ipv6", LIST, NULL, REQUIRED, write_cert_ipv6},    // ipv6 addresses
    {"as", LIST, NULL, REQUIRED, write_cert_asnums},    // as num resources
    {"signatureValue", OCTETSTRING, NULL, OPTIONAL, NULL},    // sig
    {"selfsigned", TEXT, NULL, OPTIONAL, NULL}, // true or false
    {NULL, 0, NULL, REQUIRED, NULL}
};

struct object_field *get_cert_field_table(
    )
{
    return cert_field_table;
}

/*
 * Take values from the parents certificateand write them to the 
 * current certificate.
 * val is filename of the parent certificate
 * fields of interest:
 *    signature algorithm ID - overwrite (from template)
 *    issuer     - if filled in then don't overwrite
 *    aki        - use ski from issuer's cert
 *    algorithm ID  overwrite (from template)
 */
int use_parent_cert(
    void *cert,
    void *val)
{
    struct Certificate issuer;
    struct Certificate *certp = (struct Certificate *)cert;
    struct CertificateToBeSigned *ctftbsp = &certp->toBeSigned;
    Certificate(&issuer, (ushort) 0);
    struct Extension *iextp,
       *cextp;

    // if not parent cert or we are self signed (and shouldn't have a parent
    // cert)
    if ((val == NULL) || (selfSigned))
        return SUCCESS;

    // fprintf(stdout,"getting issuers cert %s\n", (char *)val);
    if (get_casn_file(&issuer.self, val, 0) < 0)
    {
        fprintf(stdout, "can't use issuers cert %s", (char *)val);
        return -1;
    }
    // copy algorithm identifiers (overwrite template value)
    // fprintf(stdout,"trying to copy algorithm identifiers\n");
    copy_casn(&certp->algorithm.self, &issuer.toBeSigned.signature.self);
    copy_casn(&ctftbsp->signature.self, &issuer.toBeSigned.signature.self);
    // fprintf(stdout,"copied algorithm identifiers\n");

    // copy subject name from issuer cert into issuer name in cert if issuer
    // name
    // not filled in.
    copy_casn(&ctftbsp->issuer.self, &issuer.toBeSigned.subject.self);
    // fprintf(stdout,"copied issuer name\n");

    // replace aki extension of certificate with ski from issuer's cert
    cextp = find_extension(&ctftbsp->extensions, id_authKeyId, false);
    if (!cextp)
        cextp = make_extension(&ctftbsp->extensions, id_authKeyId);
    // fprintf(stdout,"copying ski as aki\n");
    if ((iextp = find_extension(&issuer.toBeSigned.extensions,
                                id_subjectKeyIdentifier, false)))
    {
        copy_casn(&cextp->extnValue.authKeyId.keyIdentifier,
                  &iextp->extnValue.subjectKeyIdentifier);
    }
    else
    {
        fprintf(stdout, "Error: issuer cert has no SKI. AKI not set.");
        delete_casn(&issuer.self);
        return -1;
    }

    delete_casn(&issuer.self);
    return (SUCCESS);
}


int write_default_fields(
    struct Certificate *certp)
{

    struct CertificateToBeSigned *ctftbsp = &certp->toBeSigned;
    struct Extension *cextp;


    // key usage
    // If ca set keyCertSign and CRLsign bits
    // if ee set digitalSignature bit
    if (!(cextp = find_extension(&ctftbsp->extensions, id_keyUsage, false)))
        cextp = make_extension(&ctftbsp->extensions, id_keyUsage);
    if (eecert)
    {                           // clear everything first
        write_casn_num(&cextp->critical, 1);
        write_casn(&cextp->extnValue.keyUsage.self, (uchar *) "", 0);
        write_casn_bit(&cextp->extnValue.keyUsage.digitalSignature, 1);
    }
    else
    {
        write_casn_num(&cextp->critical, 1);
        write_casn(&cextp->extnValue.keyUsage.self, (uchar *) "", 0);
        write_casn_bit(&cextp->extnValue.keyUsage.keyCertSign, 1);
        write_casn_bit(&cextp->extnValue.keyUsage.cRLSign, 1);
    }

    // basic constraints
    // if ee no extension, if ca set ca to one
    cextp = find_extension(&ctftbsp->extensions, id_basicConstraints, false);
    if (eecert)
    {
        // no basic constraints extension for an ee cert
        if (cextp)
            removeExtension(&ctftbsp->extensions, id_basicConstraints);
    }
    else
    {
        int caConstraint = 1;
        if (!cextp)
            cextp = make_extension(&ctftbsp->extensions, id_basicConstraints);
        write_casn_num(&cextp->critical, 1);
        // write_casn(&cextp->extnValue.basicConstraints.self, (uchar *)"",
        // 0); 
        write_casn_num(&cextp->extnValue.basicConstraints.cA, caConstraint);
    }

    return SUCCESS;
}


/*
 * Take values from the subject keyfile and write them to the 
 * current certificate.
 * val is filename of the subject keyfile
 * values of interest are the subject public key and the ski.
 */
int use_subject_keyfile(
    void *cert,
    void *val)
{
    struct Certificate *certp = (struct Certificate *)cert;
    struct CertificateToBeSigned *ctftbsp = &certp->toBeSigned;
    struct SubjectPublicKeyInfo *spkinfop = &ctftbsp->subjectPublicKeyInfo;
    struct Extensions *extsp = &ctftbsp->extensions;
    struct Extension *extp;
    struct casn *spkp = &spkinfop->subjectPublicKey;


    if (val == NULL)
        return -1;

    // if no subjectPublicKey in the cert then get if from keyfile
    if (vsize_casn(&spkinfop->subjectPublicKey) <= 0)
    {
        write_objid(&spkinfop->algorithm.algorithm, id_rsadsi_rsaEncryption);
        write_casn(&spkinfop->algorithm.parameters.rsadsi_rsaEncryption,
                   (uchar *) "", 0);
        if (!fillPublicKey(spkp, val))
            return -1;
    }

    // always update SKI to match subjectPublicKey
    if (!(extp = find_extension(extsp, id_subjectKeyIdentifier, false)))
        extp = make_extension(extsp, id_subjectKeyIdentifier);
    writeHashedPublicKey(&extp->extnValue.subjectKeyIdentifier, spkp, false);

    return (SUCCESS);
}

/*
 * Write the serial number into the certiifcate
 * Value is a string integer
 */
int write_serialNum(
    void *cert,
    void *val)
{
    int snum;
    struct CertificateToBeSigned *tbs =
        &((struct Certificate *)cert)->toBeSigned;

    snum = atoi(val);
    // fprintf(stdout, "Writing Serial Number %d to Certificate\n",snum);

    if (write_casn_num(&tbs->serialNumber, snum) < 0)
        return -1;
    return SUCCESS;
}

/*
 * Write common name into name of cert
 */
int add_cn(
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
int add_sn(
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
 * Write the issuer name to the certificate
 * The value is the issuer name as a printable string.
 * It can be the commonName%SerialNumber.If the % is in the
 * string the the first half is commonName and the second half is
 * the serialNum. i.e. val= "Gollum" or val="Bilbo Baggins%135AXZ79"
 */
int write_issuer_name(
    void *cert,
    void *val)
{

    struct CertificateToBeSigned *tbs =
        &((struct Certificate *)cert)->toBeSigned;
    char token = '%';
    char *sn = NULL;
    int len;
    struct RDNSequence *rdnsp;
    struct RelativeDistinguishedName *rdnp;

    // if we are self signed we get the issuer name from the subject name
    if (selfSigned)
        return SUCCESS;

    clear_casn(&tbs->issuer.self);
    sn = strchr(val, token);
    // fprintf(stdout, "Writing Issuer Name %s to Certificate\n",(char *)val
    // );

    rdnsp = (struct RDNSequence *)&tbs->issuer.rDNSequence;

    rdnp = (struct RelativeDistinguishedName *)inject_casn(&rdnsp->self, 0);
    if (rdnp == NULL)
        return -1;

    if (sn != NULL)
    {
        len = (char *)sn - (char *)val;
        sn++;
        if ((add_cn(rdnp, (char *)val, len) == 0) &&
            (add_sn(rdnp, (char *)sn, strlen(sn)) == 0))
            return (SUCCESS);
    }
    else
    {
        if (add_cn(rdnp, val, strlen(val)) == 0)
            return SUCCESS;
    }
    return -1;
}

/*
 * Write the subject name to the certificate
 * The value is the subject name as a printable string.
 * It can be the commonName%SerialNumber.If the % is in the
 * string the the first half is commonName and the second half is
 * the serialNum. i.e. val= "Gollum" or val="Bilbo Baggins%135AXZ79"
 *
 */
int write_subject_name(
    void *cert,
    void *val)
{

    struct CertificateToBeSigned *tbs =
        &((struct Certificate *)cert)->toBeSigned;
    char token = '%';
    char *sn = NULL;
    int len;
    struct RDNSequence *rdnsp;
    struct RelativeDistinguishedName *rdnp;
    int done = 0,
        issuer = 0;
    int ret = SUCCESS;

    while (!done)
    {
        sn = strchr(val, token);

        if (issuer)
            rdnsp = (struct RDNSequence *)&tbs->issuer.rDNSequence;
        else
            rdnsp = (struct RDNSequence *)&tbs->subject.rDNSequence;

        rdnp =
            (struct RelativeDistinguishedName *)inject_casn(&rdnsp->self, 0);
        if (rdnp == NULL)
            return -1;

        if (sn != NULL)
        {
            len = (char *)sn - (char *)val;
            sn++;
            if ((add_cn(rdnp, (char *)val, len) == 0) &&
                (add_sn(rdnp, (char *)sn, strlen(sn)) == 0))
                ret = SUCCESS;
        }
        else
            ret = add_cn(rdnp, val, strlen(val));

        if (selfSigned && !issuer)
            issuer = 1;         // set issuer name to this subject name
        else
            done = 1;
    }
    return ret;
}

/*
 * Write out the notBefore validity date
 */
int write_notBefore_time(
    void *cert,
    void *val)
{
    struct CertificateToBeSigned *tbsp =
        &((struct Certificate *)cert)->toBeSigned;
    int len,
        ret;
    int utclen = 13;
    int glen = 15;

    if (val == NULL)
        return -1;

    // fprintf(stdout, "Not Before is %s\n", (char *)val);
    len = strlen(val);

    if (len == utclen)
        ret = write_casn(&tbsp->validity.notBefore.utcTime,
                         (uchar *) val, strlen(val));
    else if (len == glen)
        ret = write_casn(&tbsp->validity.notBefore.generalTime,
                         (uchar *) val, strlen(val));
    else
        ret = -1;

    if (ret > 0)
        return (SUCCESS);

    return -1;
}

/*
 *
 */
int write_notAfter_time(
    void *cert,
    void *val)
{
    struct CertificateToBeSigned *tbsp =
        &((struct Certificate *)cert)->toBeSigned;
    int len,
        ret;
    int utclen = 13;
    int glen = 15;

    if (val == NULL)
        return -1;

    // fprintf(stdout, "Not After is %s\n", (char *)val);
    len = strlen(val);

    if (len == utclen)
        ret = write_casn(&tbsp->validity.notAfter.utcTime,
                         (uchar *) val, strlen(val));
    else if (len == glen)
        ret = write_casn(&tbsp->validity.notAfter.generalTime,
                         (uchar *) val, strlen(val));
    else
        ret = -1;

    if (ret > 0)
        return (SUCCESS);

    return -1;
}

/*
 * Write the subject public key info. It is a comma-separated pair of 
 * hex integers: "0xXX,0xYY". Currently, RSA is the only allowed algorithm
 * for the RPKI, so the public key information is defined as modulus followed
 * by publicExponent.
 */
int write_cert_pubkey(
    void *cert,
    void *val)
{
    struct CertificateToBeSigned *tbsp =
        &((struct Certificate *)cert)->toBeSigned;
    struct SubjectPublicKeyInfo *spkinfop = &tbsp->subjectPublicKeyInfo;
    char token = ',';
    int mod_len,
        exp_len;
    char *mod = val;
    unsigned char *mkey = NULL;
    unsigned char *ekey = NULL;
    char *pExp = NULL;
    int bytes_written;
    struct RSAPubKey rpk;

    RSAPubKey(&rpk, 0);
    pExp = strchr(val, token);

    // strip off leading spaces and the 0x
    while (isspace((int)(unsigned char)*mod))
        mod++;
    if (strncmp(mod, "0x", 2) != 0)
        return -1;
    mod += 2;

    mod_len = (char *)pExp - (char *)mod;

    pExp++;
    while (isspace((int)(unsigned char)*pExp))
        pExp++;
    if (strncmp(pExp, "0x", 2) != 0)
        return -1;
    pExp += 2;

    exp_len = strlen(pExp);
    // fprintf(stdout, "exponent is: %s, len is %d\n", pExp, exp_len);

    mkey = calloc(mod_len / 2 + 1, sizeof(char));
    ekey = calloc(exp_len / 2 + 1, sizeof(char));
    if ((bytes_written = read_hex_val(mod, mod_len, mkey)) <= 0)
    {
        fprintf(stdout, "error converting modulus for public key (%s)\n",
                (char *)val);
        return -1;
    }
    if (write_casn(&rpk.modulus, mkey, bytes_written) < 0)
    {
        free(mkey);
        return -1;
    }
    free(mkey);
    if ((bytes_written = read_hex_val(pExp, exp_len, ekey)) <= 0)
    {
        fprintf(stdout, "error converting exp for public key (%s)\n",
                (char *)pExp);
        free(ekey);
        return -1;
    }
    // fprintf(stdout, "bytes written are %d\n", bytes_written); 
    if (write_casn(&rpk.exponent, ekey, bytes_written) < 0)
    {
        free(ekey);
        return -1;
    }
    // rsa is the only allowed algorithm for rpki
    free(ekey);
    write_objid(&spkinfop->algorithm.algorithm, id_rsadsi_rsaEncryption);
    write_casn(&spkinfop->algorithm.parameters.rsadsi_rsaEncryption,
               (unsigned char *)"", 0);

    int lth;
    uchar *enc_string;
    lth = size_casn(&rpk.self);
    enc_string = (uchar *) calloc(1, lth);
    lth = encode_casn(&rpk.self, enc_string);

    write_casn(&spkinfop->subjectPublicKey, (unsigned char *)enc_string, lth);
    free(enc_string);
    return SUCCESS;
}


int write_sig(
    struct Certificate *cert,
    char *val)
{
    struct CertificateToBeSigned *tbsp =
        &((struct Certificate *)cert)->toBeSigned;
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

    if (write_casn(&cert->signature, sig, bytes_written) < 0)
    {
        free(sig);
        return -1;
    }



    free(sig);
    write_objid(&tbsp->signature.algorithm, id_sha_256WithRSAEncryption);
    write_casn(&tbsp->signature.parameters.rsadsi_SHA256_WithRSAEncryption,
               (uchar *) "", 0);
    write_objid(&cert->algorithm.algorithm, id_sha_256WithRSAEncryption);
    write_casn(&cert->algorithm.parameters.rsadsi_SHA256_WithRSAEncryption,
               (uchar *) "", 0);
    return SUCCESS;
}

int write_key_identifier(
    struct Certificate *cert,
    char *id,
    char *val)
{
    struct CertificateToBeSigned *tbsp =
        &((struct Certificate *)cert)->toBeSigned;
    int str_len,
        ki_len;
    char *str_ki = val;
    unsigned char *ki = NULL;
    int bytes_written;
    struct Extension *extp;
    struct Extensions *extsp = &tbsp->extensions;

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
    extp = make_extension(extsp, id);
    if (strncmp(id, id_subjectKeyIdentifier, strlen(id_subjectKeyIdentifier))
        == 0)
    {
        write_casn(&extp->extnValue.subjectKeyIdentifier, ki, bytes_written);
        free(ki);
    }
    else if (strncmp(id, id_authKeyId, strlen(id_authKeyId)) == 0)
    {
        write_casn(&extp->extnValue.authKeyId.keyIdentifier, ki,
                   bytes_written);
        free(ki);
    }
    else
        return -1;

    return SUCCESS;
}


/*
 *
 */
int write_cert_ski(
    void *cert,
    void *val)
{
    int ret;

    // if this is a self signed cert, write the ski into the ski and aki
    ret = write_key_identifier(cert, id_subjectKeyIdentifier, val);
    if (selfSigned && (ret == SUCCESS))
        ret = write_key_identifier(cert, id_authKeyId, val);

    return (ret);
}

/*
 *
 */
int write_cert_aki(
    void *cert,
    void *val)
{

    // if self signed don't write aki from command, using the ski
    if (selfSigned)
    {
        // warn aki ignored
        return SUCCESS;
    }
    return (write_key_identifier(cert, id_authKeyId, val));

}

/*
 * Write the comma separated list of ascii strings into the CRL distribution
 * point extension
 */
int write_cert_crldp(
    void *cert,
    void *val)
{
    struct CertificateToBeSigned *tbsp =
        &((struct Certificate *)cert)->toBeSigned;
    struct Extension *extp;
    struct Extensions *extsp = &tbsp->extensions;
    struct DistributionPoint *distp;
    struct GeneralName *gennamep;
    char *ptr,
       *next;
    int numpts = 0,
        ptr_len;
    char token = ',';

    if (selfSigned)
    {
        // warn ignored
        return SUCCESS;
    }
    // separate out the crldp's and write each one into the sequence
    extp = make_extension(extsp, id_cRLDistributionPoints);
    ptr = val;
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
            next++;
        }

        distp =
            (struct DistributionPoint *)inject_casn(&extp->extnValue.
                                                    cRLDistributionPoints.self,
                                                    numpts++);
        if (!distp)
            return -1;
        gennamep =
            (struct GeneralName *)inject_casn(&distp->distributionPoint.
                                              fullName.self, 0);
        if (!gennamep)
            return -1;
        write_casn(&gennamep->url, (uchar *) ptr, ptr_len);
        ptr = next;
    }

    return SUCCESS;
}


/*
 * Subject Information Access - comma separated ASCII strings
 */
int write_cert_sia(
    void *cert,
    void *val)
{
    struct CertificateToBeSigned *tbsp =
        &((struct Certificate *)cert)->toBeSigned;
    struct Extension *extp;
    struct Extensions *extsp = &tbsp->extensions;
    struct SubjectInfoAccess *siap;
    struct AccessDescription *accdsp;
    char *ptr,
       *next;
    int numpts = 0,
        ptr_len;
    char token = ',';

    // FIXME - can have 3 object identifiers, have to parse out
    // r:, m: or s: for the different ones.

    // separate out the sia's and write each one into the sequence
    extp = make_extension(extsp, id_pe_subjectInfoAccess);
    ptr = val;
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
            next++;
        }

        siap = &extp->extnValue.subjectInfoAccess;
        accdsp =
            (struct AccessDescription *)inject_casn(&siap->self, numpts++);
        if (!accdsp)
            return -1;

        // parse out what object id to use
        // s - signedOjbect, r - caRepository, m - manifest
        if (strncmp(ptr, "r:", strlen("r:")) == 0)
            write_objid(&accdsp->accessMethod, id_ad_caRepository);
        else if (strncmp(ptr, "s:", strlen("s:")) == 0)
            write_objid(&accdsp->accessMethod, id_ad_signedObject);
        else if (strncmp(ptr, "m:", strlen("m:")) == 0)
            write_objid(&accdsp->accessMethod, id_ad_rpkiManifest);
        else
            return -1;

        ptr += 2;               // jump over the object id designation
        ptr_len -= 2;
        write_casn(&accdsp->accessLocation.url, (unsigned char *)ptr, ptr_len);
        ptr = next;
    }
    return SUCCESS;
}

/*
 *
 */
int write_cert_aia(
    void *cert,
    void *val)
{
    struct CertificateToBeSigned *tbsp =
        &((struct Certificate *)cert)->toBeSigned;
    struct Extension *extp;
    struct Extensions *extsp = &tbsp->extensions;
    struct AuthorityInfoAccessSyntax *aiasp;
    struct AccessDescription *accdsp;
    char *ptr = (char *)val;

    if (selfSigned)
    {
        // warn ignored
        return SUCCESS;
    }

    extp = make_extension(extsp, id_pkix_authorityInfoAccess);
    while (isspace((int)(unsigned char)*ptr))
        ptr++;                  // strip leading spaces

    aiasp = &extp->extnValue.authorityInfoAccess;
    accdsp = (struct AccessDescription *)inject_casn(&aiasp->self, 0);
    write_objid(&accdsp->accessMethod, id_ad_caIssuers);
    write_casn(&accdsp->accessLocation.url, (unsigned char *)ptr, strlen(ptr));

    return SUCCESS;
}

/*
 * ipv4 address are a comma separated list of either prefix or range
 * specifications for ipv4 addresses
 */
int write_cert_addrs(
    void *cert,
    void *val,
    int type)
{
    struct CertificateToBeSigned *tbsp =
        &((struct Certificate *)cert)->toBeSigned;
    struct Extension *extp;
    struct Extensions *extsp = &tbsp->extensions;
    struct IPAddressFamilyA *famp;
    char *ptr,
       *next,
       *buf;
    int ptr_len;
    char token = ',';
    char family[2];
    int num = 0;

    family[0] = 0;
    if (type == IPv4)
        family[1] = 1;
    else
        family[1] = 2;

    extp = find_extension(extsp, id_pe_ipAddrBlock, false);
    if (!extp)
    {
        extp = make_extension(extsp, id_pe_ipAddrBlock);
        write_casn_num(&extp->critical, 1);
    }

    if (type == IPv6)
        famp =
            (struct IPAddressFamilyA *)inject_casn(&extp->extnValue.
                                                   ipAddressBlock.self,
                                                   num_items(&extp->extnValue.
                                                             ipAddressBlock.
                                                             self));
    else
        famp =
            (struct IPAddressFamilyA *)inject_casn(&extp->extnValue.
                                                   ipAddressBlock.self, 0);

    write_casn(&famp->addressFamily, (unsigned char *)family, 2);

    // if it is inherit - set that and done
    if (strncmp(val, "inherit", strlen("inherit")) == 0)
    {
        struct IPAddressChoiceA *addrChoice = &famp->ipAddressChoice;
        write_casn(&addrChoice->inherit, (uchar *) "", 0);
        return SUCCESS;
    }

    // go through all addresses listed and add them to the block
    ptr = val;
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
            next++;
        }
        if ((buf = strndup(ptr, ptr_len)) == NULL)
            return -1;

        if (write_family(famp, buf, num++) < 0)
            return -1;
        ptr = next;
    }

    return SUCCESS;
}

/*
 * ipv4 address are a comma separated list of either prefix or range
 * specifications for ipv4 addresses
 */
int write_cert_ipv4(
    void *cert,
    void *val)
{
    return (write_cert_addrs(cert, val, IPv4));
}

/*
 *
 */
int write_cert_ipv6(
    void *cert,
    void *val)
{
    return (write_cert_addrs(cert, val, IPv6));
}

/*
 *
 */
int write_cert_asnums(
    void *cert,
    void *val)
{

    struct CertificateToBeSigned *tbsp =
        &((struct Certificate *)cert)->toBeSigned;
    struct Extension *extp;
    char *ptr,
       *next,
       *buf;
    int ptr_len;
    char token = ',';
    int num = 0;

    extp = make_extension(&tbsp->extensions, id_pe_autonomousSysNum);
    write_casn_num(&extp->critical, 1);
    struct ASNum *asNump = &extp->extnValue.autonomousSysNum;


    // if it is inherit - set that and done
    if (strncasecmp(val, "inherit", strlen("inherit")) == 0)
    {
        struct ASIdentifierChoiceA *asidChoice = &asNump->asnum;
        write_casn(&asidChoice->inherit, (uchar *) "", 0);
        return SUCCESS;
    }

    // go through all as numbers listed and add them to the block
    ptr = val;
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
            next++;
        }

        if ((buf = strndup(ptr, ptr_len)) == NULL)
            return -1;

        if (write_ASNums(asNump, buf, num++) < 0)
            return -1;

        free(buf);
        ptr = next;
    }

    return SUCCESS;
}

// clear out the fields that must be filled in
void clear_cert(
    struct Certificate *certp)
{
    struct CertificateToBeSigned *tbsp = &certp->toBeSigned;

    clear_casn(&tbsp->serialNumber);
    clear_casn(&tbsp->issuer.self);
    clear_casn(&tbsp->subject.self);
    clear_casn(&tbsp->validity.self);
    clear_casn(&tbsp->subjectPublicKeyInfo.self);
    clear_casn(&certp->signature);
}

void setSelfSigned(
    struct object_field *table)
{
    char *val;
    int val_type;

    // if self signed is true, set self signed bit and type to CA
    if (get_table_value("selfsigned", table, &val, &val_type) >= 0)
    {
        if ((val != NULL) && (strncasecmp(val, "true", strlen("true")) == 0))
        {
            selfSigned = 1;
            eecert = 0;
        }
    }
}

int setEEorCA(
    struct object_field *table)
{
    char *val;
    int val_type;

    if (get_table_value("type", table, &val, &val_type) < 0)
    {
        warn(MISSING_CERT_TYPE, NULL);
        return (MISSING_CERT_TYPE);
    }
    if (strncasecmp(val, "EE", strlen("EE")) == 0)
        eecert = 1;

    return SUCCESS;
}


/*
 * Create an EE or CA certificate using the
 * table to set the fields. The table is build
 * using command line arguments
 */
int create_cert(
    struct object_field *table)
{

    int ret = 0;
    int i;
    struct Certificate cert;
    Certificate(&cert, (ushort) 0);     // constructor for the cert struct
    char *keyfile = NULL,
        *val;
    int val_type;

    eecert = 0;

    // is it a ca or ee cert
    if ((ret = setEEorCA(table)) != SUCCESS)
        return ret;

    setSelfSigned(table);

    // Read the certificate template into the certificate
    if (!templateFile)
    {
        if (eecert)
            templateFile = eecert_template;
        else
            templateFile = cacert_template;
    }
    ret = get_casn_file(&cert.self, (char *)templateFile, 0);
    if (ret < 0)
    {
        warn(FILE_OPEN_ERR, (char *)templateFile);
        return (FILE_OPEN_ERR);
    }

    // clear out fields in the template (only keeping a few);
    clear_cert(&cert);

    // fill in the default fields
    write_default_fields(&cert);

    // Populate the certificate fields with data from the 
    // table. Note the table is populated from input arguments
    // If there is no function to call and the argument is optional then
    // it is ok otherwise it is an error.
    for (i = 0; table[i].name != NULL; i++)
    {
        if (table[i].func != NULL)
        {
            if (table[i].value != NULL)
            {
                if (table[i].func(&cert.self, table[i].value) < 0)
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
        if (write_sig(&cert, val) != SUCCESS)
        {
            fprintf(stdout, "Error writing signature");
            return (-1);
        }
    }
    else
    {                           // have to sign it, get key from subject
                                // keyfile if selfsigned else parents
        if (selfSigned)
            get_table_value("subjkeyfile", table, &keyfile, &val_type);
        else
            get_table_value("parentkeyfile", table, &keyfile, &val_type);

        if (keyfile == NULL || (sign_cert(&cert, keyfile) != SUCCESS))
            return -1;
    }

    // write out the certificate using the ouput filename
    if (get_table_value("outputfilename", table, &val, &val_type) < 0)
    {
        warn(FILE_WRITE_ERR, "outputfilename missing");
        return (FILE_WRITE_ERR);
    }
    if (put_casn_file(&cert.self, val, 0) < 0)
    {
        warn(FILE_WRITE_ERR, val);
        return (FILE_WRITE_ERR);
    }
    else
        warn(SUCCESS, val);

    return (SUCCESS);

}
