/** @file */

#include "myssl.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <getopt.h>
#include <time.h>
#include <limits.h>
#include <util/cryptlib_compat.h>
#include <stdbool.h>

#include "globals.h"
#include "util/hashutils.h"
#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "err.h"
#include "util/logging.h"
#include "rpwork.h"
#include "rpki-asn1/crlv2.h"
#include "util/stringutils.h"

int strict_profile_checks = 0;

#define UTC10    10             // UTC format without seconds
#define UTC12    12             // UTC format with seconds
#define GEN14    14             // generalized format without fractions of a
                                // second
#define GEN16    16             // generalized format with fractions of a
                                // second

char *ASNTimeToDBTime(
    char *bef,
    err_code *stap,
    int only_gentime)
{
    LOG(LOG_DEBUG, "ASNTimeToDBTime(bef=\"%s\", stap=%p, only_gentime=%d)",
        bef, stap, only_gentime);

    int year;
    int mon;
    int day;
    int suf_hour = 0;
    int hour;
    int suf_min = 0;
    int min;
    int sec;
    int msec;
    int cnt;
    int fmt = 0;
    char tz = 0;
    char *ptr;
    char *out = NULL;

    if (stap == NULL)
    {
        goto done;
    }
    *stap = 0;
    if (bef == NULL || bef[0] == 0)
    {
        *stap = ERR_SCM_INVALARG;
        goto done;
    }
    // first find and parse the suffix if any
    ptr = strpbrk(bef, "+-");
    if (ptr != NULL)
    {
        cnt = sscanf(ptr + 1, "%2d%2d", &suf_hour, &suf_min);
        if (cnt != 2 || suf_hour < 0 || suf_hour > 24 ||
            suf_min < 0 || suf_min > 60)
        {
            *stap = ERR_SCM_INVALDT;
            goto done;
        }
        if (*ptr == '-')
        {
            suf_hour = -suf_hour;
            suf_min = -suf_min;
        }
    }
    // next, determine how many characters there are before the tz indicator
    ptr = strchr(bef, 'Z');
    if (ptr == NULL)
    {
        *stap = ERR_SCM_INVALDT;
        goto done;
    }
    fmt = (int)(ptr - bef);
    switch (fmt)
    {
    case UTC10:
        sec = 0;
        cnt = sscanf(bef, "%2d%2d%2d%2d%2d%c", &year, &mon, &day,
                     &hour, &min, &tz);
        if (cnt != 6)
        {
            *stap = ERR_SCM_INVALDT;
            goto done;
        }
        if (year > 49)
            year += 1900;
        else
            year += 2000;
        break;
    case UTC12:
        cnt = sscanf(bef, "%2d%2d%2d%2d%2d%2d%c", &year, &mon, &day,
                     &hour, &min, &sec, &tz);
        if (cnt != 7)
        {
            *stap = ERR_SCM_INVALDT;
            goto done;
        }
        if (year > 49)
            year += 1900;
        else
            year += 2000;
        break;
    case GEN14:
        cnt = sscanf(bef, "%4d%2d%2d%2d%2d%2d%c", &year, &mon, &day,
                     &hour, &min, &sec, &tz);
        if (cnt != 7)
        {
            *stap = ERR_SCM_INVALDT;
            goto done;
        }
        break;
    case GEN16:
        cnt = sscanf(bef, "%4d%2d%2d%2d%2d%2d.%1d%c", &year, &mon, &day,
                     &hour, &min, &sec, &msec, &tz);
        if (cnt != 8)
        {
            *stap = ERR_SCM_INVALDT;
            goto done;
        }
        break;
    default:
        *stap = ERR_SCM_INVALDT;
        goto done;
    }
    // validate the time with the suffix
    if (tz != 'Z' || mon < 1 || mon > 12 || day < 1 || day > 31 || hour < 0 ||
        hour > 23 || min < 0 || min > 59 || sec < 0 || sec > 61)
        /*
         * 61 because of leap seconds
         */
    {
        *stap = ERR_SCM_INVALDT;
        goto done;
    }
    // we should adjust the time if there is a suffix, but currently we don't
    // next check that the format matches the year. If the year is < 2050
    // it should be UTC, otherwise GEN.
    if (only_gentime)
    {
        if (fmt != GEN14 && fmt != GEN16)
        {
            *stap = ERR_SCM_INVALDT;
            goto done;
        }
    }
    else
    {
        if (year < 2050 && (fmt == GEN14 || fmt == GEN16))
        {
            *stap = ERR_SCM_INVALDT;
            goto done;
        }
        if (year >= 2050 && (fmt == UTC10 || fmt == UTC12))
        {
            *stap = ERR_SCM_INVALDT;
            goto done;
        }
    }
    out = (char *)calloc(48, sizeof(char));
    if (out == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        goto done;
    }
    xsnprintf(out, 48, "%4d-%02d-%02d %02d:%02d:%02d",
              year, mon, day, hour, min, sec);
done:
    LOG(LOG_DEBUG, "ASNTimeToDBTime() returning \"%s\" with error code %s: %s",
        out, stap ? err2name(*stap) : "NULL",
        stap ? err2string(*stap) : "NULL");
    return (out);
}

char *LocalTimeToDBTime(
    err_code *stap)
{
    time_t clck;
    (void)time(&clck);
    return UnixTimeToDBTime(clck, stap);
}

char *UnixTimeToDBTime(
    time_t clck,
    err_code *stap)
{
    struct tm *tmp;
    char *out;
    err_code sta = 0;

    out = (char *)calloc(48, sizeof(char));
    if (out == NULL)
    {
        sta = ERR_SCM_NOMEM;
        goto done;
    }
    tmp = gmtime(&clck);
    xsnprintf(out, 48, "%d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d",
              1900 + tmp->tm_year, 1 + tmp->tm_mon, tmp->tm_mday,
              tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
done:
    if (stap)
    {
        *stap = sta;
    }
    return (out);
}

void freecf(
    cert_fields *cf)
{
    int i;

    if (cf == NULL)
        return;
    for (i = 0; i < CF_NFIELDS; i++)
    {
        if (cf->fields[i] != NULL)
        {
            free((void *)(cf->fields[i]));
            cf->fields[i] = 0;
        }
    }
    if (cf->ipb != NULL)
    {
        free(cf->ipb);
        cf->ipb = NULL;
    }
    cf->ipblen = 0;
    free((void *)cf);
}

void freecrf(
    crl_fields *cf)
{
    int i;

    if (cf == NULL)
        return;
    for (i = 0; i < CRF_NFIELDS; i++)
    {
        if (cf->fields[i] != NULL)
        {
            free((void *)(cf->fields[i]));
            cf->fields[i] = 0;
        }
    }
    if (cf->snlist != NULL)
    {
        free(cf->snlist);
        cf->snlist = NULL;
    }
    free((void *)cf);
}

static char *strappend(
    char *instr,
    char *nstr)
{
    char *outstr;
    int leen;

    if (nstr == NULL || nstr[0] == 0)
        return (instr);
    if (instr == NULL)
        return (strdup(nstr));
    leen = strlen(instr) + strlen(nstr) + 24;
    outstr = (char *)calloc(leen, sizeof(char));
    if (outstr == NULL)
        return (instr);
    xsnprintf(outstr, leen, "%s;%s", instr, nstr);
    free((void *)instr);
    return (outstr);
}

static char *addgn(
    char *ptr,
    GENERAL_NAME * gen)
{
    char oline[1024];
    char *optr = ptr;

    if (gen == NULL)
        return (ptr);
    switch (gen->type)
    {
    case GEN_EMAIL:
    case GEN_DNS:
    case GEN_URI:
        optr = strappend(ptr, (char *)(gen->d.ia5->data));
        break;
    case GEN_DIRNAME:
        oline[0] = 0;
        X509_NAME_oneline(gen->d.dirn, oline, 1024);
        if (oline[0] != 0)
            optr = strappend(ptr, oline);
    }
    return (optr);
}

static cf_get cf_get_subject;
char *
cf_get_subject(
    X509 *x,
    err_code *stap,
    int *x509stap)
{
    char *ptr;
    char *dptr;

    if (x == NULL || stap == NULL || x509stap == NULL)
        return (NULL);
    ptr = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);
    if (ptr == NULL)
    {
        *stap = ERR_SCM_NOSUBJECT;
        return (NULL);
    }
    dptr = strdup(ptr);
    OPENSSL_free(ptr);
    if (dptr == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        return (NULL);
    }
    return (dptr);
}

/*
 * This is a public version of the above.
 */

char *X509_to_subject(
    X509 *x,
    err_code *stap,
    int *x509stap)
{
    return cf_get_subject(x, stap, x509stap);
}

static cf_get cf_get_issuer;
char *
cf_get_issuer(
    X509 *x,
    err_code *stap,
    int *x509stap)
{
    char *ptr;
    char *dptr;

    if (x == NULL || stap == NULL || x509stap == NULL)
        return (NULL);
    ptr = X509_NAME_oneline(X509_get_issuer_name(x), NULL, 0);
    if (ptr == NULL)
    {
        *stap = ERR_SCM_NOISSUER;
        return (NULL);
    }
    dptr = strdup(ptr);
    OPENSSL_free(ptr);
    if (dptr == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        return (NULL);
    }
    return (dptr);
}

static cf_get cf_get_sn;
char *
cf_get_sn(
    X509 *x,
    err_code *stap,
    int *x509stap)
{
    ASN1_INTEGER *a1;
    BIGNUM *bn;
    char *ptr;
    char *dptr;
    size_t len;
    size_t i, j;

    if (x == NULL || stap == NULL || x509stap == NULL)
        return (NULL);
    a1 = X509_get_serialNumber(x);
    if (a1 == NULL)
    {
        *stap = ERR_SCM_NOSN;
        return (NULL);
    }
    bn = ASN1_INTEGER_to_BN(a1, NULL);
    if (bn == NULL)
    {
        *stap = ERR_SCM_BIGNUMERR;
        return (NULL);
    }
    ptr = BN_bn2hex(bn);
    if (ptr == NULL)
    {
        BN_free(bn);
        *stap = ERR_SCM_BIGNUMERR;
        return (NULL);
    }
    dptr = malloc(2 + 2*SER_NUM_MAX_SZ + 1); // "^x" and null terminator
    if (dptr != NULL)
    {
        len = strlen(ptr);
        if (len > 2*SER_NUM_MAX_SZ)
        {
            *stap = ERR_SCM_BADSERNUM;
            OPENSSL_free(ptr);
            BN_free(bn);
            return (NULL);
        }
        i = 0;
        dptr[i++] = '^';
        dptr[i++] = 'x';
        for (j = 0; j < 2*SER_NUM_MAX_SZ - len; ++j)
        {
            dptr[i++] = '0';
        }
        for (j = 0; j < len; ++j)
        {
            dptr[i++] = ptr[j];
        }
        dptr[i++] = '\0';
    }
    OPENSSL_free(ptr);
    BN_free(bn);
    if (dptr == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        return (NULL);
    }
    return (dptr);
}

static cf_get cf_get_from;
char *
cf_get_from(
    X509 *x,
    err_code *stap,
    int *x509stap)
{
    ASN1_GENERALIZEDTIME *nb4;
    unsigned char *bef = NULL;
    char *dptr;
    int asn1sta;

    nb4 = X509_get_notBefore(x);
    if (nb4 == NULL)
    {
        *stap = ERR_SCM_NONB4;
        return (NULL);
    }
    asn1sta = ASN1_STRING_to_UTF8(&bef, (ASN1_STRING *) nb4);
    if (asn1sta < 0)            /* error */
    {
        *x509stap = asn1sta;
        *stap = ERR_SCM_X509;
        return (NULL);
    }
    if (bef == NULL || asn1sta == 0)    /* null string */
    {
        *stap = ERR_SCM_NONB4;
        return (NULL);
    }
    *stap = 0;
    dptr = ASNTimeToDBTime((char *)bef, stap, 0);
    OPENSSL_free(bef);
    if (dptr == NULL)
    {
        if (*stap == 0)
            *stap = ERR_SCM_NOMEM;
        return (NULL);
    }
    return (dptr);
}

static cf_get cf_get_to;
char *
cf_get_to(
    X509 *x,
    err_code *stap,
    int *x509stap)
{
    ASN1_GENERALIZEDTIME *naf;
    unsigned char *aft = NULL;
    char *dptr;
    int asn1sta;

    naf = X509_get_notAfter(x);
    if (naf == NULL)
    {
        *stap = ERR_SCM_NONAF;
        return (NULL);
    }
    asn1sta = ASN1_STRING_to_UTF8(&aft, (ASN1_STRING *) naf);
    if (asn1sta < 0)            /* error */
    {
        *x509stap = asn1sta;
        *stap = ERR_SCM_X509;
        return (NULL);
    }
    if (aft == NULL || asn1sta == 0)    /* null string */
    {
        *stap = ERR_SCM_NONAF;
        return (NULL);
    }
    dptr = ASNTimeToDBTime((char *)aft, stap, 0);
    OPENSSL_free(aft);
    if (dptr == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        return (NULL);
    }
    return (dptr);
}

static cf_get cf_get_sig;
char *
cf_get_sig(
    X509 *x,
    err_code *stap,
    int *x509stap)
{
    (void)x509stap;

    char *dptr;

    if (x->signature == NULL || x->signature->data == NULL ||
        x->signature->length <= 0)
    {
        *stap = ERR_SCM_NOSIG;
        return (NULL);
    }
    dptr = hexify(x->signature->length, (void *)(x->signature->data), 0);
    if (dptr == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        return (NULL);
    }
    return (dptr);
}

static cfx_get cf_get_ski;
void
cf_get_ski(
    const X509V3_EXT_METHOD *meth,
    void *exts,
    cert_fields *cf,
    err_code *stap,
    int *x509stap)
{
    char *ptr;
    char *dptr;

    if (stap == NULL)
        return;
    if (meth == NULL || exts == NULL || cf == NULL || x509stap == NULL)
    {
        *stap = ERR_SCM_INVALARG;
        return;
    }
    if (meth->i2s == NULL)
    {
        *stap = ERR_SCM_BADEXT;
        return;
    }
    ptr = meth->i2s(meth, exts);
    if (ptr == NULL || ptr[0] == 0)
    {
        *stap = ERR_SCM_BADEXT;
        return;
    }
    dptr = strdup(ptr);
    OPENSSL_free(ptr);
    if (dptr == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        return;
    }
    cf->fields[CF_FIELD_SKI] = dptr;
}

static cfx_get cf_get_aki;
void
cf_get_aki(
    const X509V3_EXT_METHOD *meth,
    void *exts,
    cert_fields *cf,
    err_code *stap,
    int *x509stap)
{
    AUTHORITY_KEYID *aki;
    char *ptr;
    char *dptr;

    if (stap == NULL)
        return;
    if (meth == NULL || exts == NULL || cf == NULL || x509stap == NULL)
    {
        *stap = ERR_SCM_INVALARG;
        return;
    }
    aki = (AUTHORITY_KEYID *) exts;
    if (aki->keyid == NULL)
    {
        *stap = ERR_SCM_XPROFILE;
        return;
    }
    ptr = hex_to_string(aki->keyid->data, aki->keyid->length);
    if (ptr == NULL)
    {
        *stap = ERR_SCM_INVALEXT;
        return;
    }
    dptr = strdup(ptr);
    OPENSSL_free(ptr);
    if (dptr == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        return;
    }
    cf->fields[CF_FIELD_AKI] = dptr;
}

static cfx_get cf_get_sia;
void
cf_get_sia(
    const X509V3_EXT_METHOD *meth,
    void *exts,
    cert_fields *cf,
    err_code *stap,
    int *x509stap)
{
    AUTHORITY_INFO_ACCESS *aia;
    ACCESS_DESCRIPTION *desc;
    GENERAL_NAME *gen;
    char *ptr = NULL;
    int i;

    if (stap == NULL)
        return;
    if (meth == NULL || exts == NULL || cf == NULL || x509stap == NULL)
    {
        *stap = ERR_SCM_INVALARG;
        return;
    }
    aia = (AUTHORITY_INFO_ACCESS *) exts;
    for (i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++)
    {
        desc = sk_ACCESS_DESCRIPTION_value(aia, i);
        if (desc != NULL)
        {
            gen = desc->location;
            if (gen != NULL)
                ptr = addgn(ptr, gen);
        }
    }
    cf->fields[CF_FIELD_SIA] = ptr;
}

static cfx_get cf_get_aia;
void
cf_get_aia(
    const X509V3_EXT_METHOD *meth,
    void *exts,
    cert_fields *cf,
    err_code *stap,
    int *x509stap)
{
    AUTHORITY_INFO_ACCESS *aia;
    ACCESS_DESCRIPTION *desc;
    GENERAL_NAME *gen;
    char *ptr = NULL;
    int i;

    if (stap == NULL)
        return;
    if (meth == NULL || exts == NULL || cf == NULL || x509stap == NULL)
    {
        *stap = ERR_SCM_INVALARG;
        return;
    }
    aia = (AUTHORITY_INFO_ACCESS *) exts;
    for (i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++)
    {
        desc = sk_ACCESS_DESCRIPTION_value(aia, i);
        if (desc != NULL)
        {
            gen = desc->location;
            if (gen != NULL)
                ptr = addgn(ptr, gen);
        }
    }
    cf->fields[CF_FIELD_AIA] = ptr;
}

static cfx_get cf_get_crldp;
void
cf_get_crldp(
    const X509V3_EXT_METHOD *meth,
    void *exts,
    cert_fields *cf,
    err_code *stap,
    int *x509stap)
{
    STACK_OF(DIST_POINT) * crld;
    GENERAL_NAMES *gen;
    GENERAL_NAME *gen1;
    DIST_POINT *point;
    char *ptr = NULL;
    int j;
    int k;

    if (stap == NULL)
        return;
    if (meth == NULL || exts == NULL || cf == NULL || x509stap == NULL)
    {
        *stap = ERR_SCM_INVALARG;
        return;
    }
    crld = (STACK_OF(DIST_POINT) *) exts;
    for (j = 0; j < sk_DIST_POINT_num(crld); j++)
    {
        point = sk_DIST_POINT_value(crld, j);
        if (point != NULL && point->distpoint != NULL &&
            point->distpoint->type == 0)
        {
            gen = point->distpoint->name.fullname;
            if (gen != NULL)
            {
                for (k = 0; k < sk_GENERAL_NAME_num(gen); k++)
                {
                    gen1 = sk_GENERAL_NAME_value(gen, k);
                    if (gen1 != NULL)
                        ptr = addgn(ptr, gen1);
                }
            }
        }
    }
    cf->fields[CF_FIELD_CRLDP] = ptr;
}

static cfx_get cf_get_flags;
void
cf_get_flags(
    const X509V3_EXT_METHOD *meth,
    void *exts,
    cert_fields *cf,
    err_code *stap,
    int *x509stap)
{
    BASIC_CONSTRAINTS *bk;
    int isca;

    UNREFERENCED_PARAMETER(meth);
    if (stap == NULL)
        return;
    if (exts == NULL || cf == NULL || x509stap == NULL)
    {
        *stap = ERR_SCM_INVALARG;
        return;
    }
    bk = (BASIC_CONSTRAINTS *) exts;
    isca = bk->ca;
    if (isca != 0)
        cf->flags |= SCM_FLAG_CA;
}

/**
 * This is the raw processing function that extracts the data/length of the
 * IPAddressBlock in the ASN.1 of the certificate and places them into the
 * corresponding cf fields.
 */
static cfx_get cf_get_ipb;
void
cf_get_ipb(
    const X509V3_EXT_METHOD *meth,
    void *ex,
    cert_fields *cf,
    err_code *stap,
    int *x509stap)
{
    X509_EXTENSION *exx;
    int leen;

    UNREFERENCED_PARAMETER(meth);
    UNREFERENCED_PARAMETER(x509stap);
    if (stap == NULL)
        return;
    exx = (X509_EXTENSION *) ex;
    leen = exx->value->length;
    if (leen <= 0)
    {
        cf->ipblen = 0;
        cf->ipb = NULL;
        return;
    }
    cf->ipb = calloc(leen, sizeof(unsigned char));
    if (cf->ipb == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        return;
    }
    memcpy(cf->ipb, exx->value->data, leen);
    cf->ipblen = leen;
}

static cfx_validator xvalidators[] = {
    {&cf_get_ski, CF_FIELD_SKI, NID_subject_key_identifier, 1, 0},
    {&cf_get_aki, CF_FIELD_AKI, NID_authority_key_identifier, 0, 0},
    {&cf_get_sia, CF_FIELD_SIA, NID_sinfo_access, 0, 0},
    {&cf_get_aia, CF_FIELD_AIA, NID_info_access, 0, 0},
    {&cf_get_crldp, CF_FIELD_CRLDP, NID_crl_distribution_points, 0, 0},
    {&cf_get_ipb, 0, NID_sbgp_ipAddrBlock, 0, 1},
    {&cf_get_flags, 0, NID_basic_constraints, 0, 0}
};

/*
 * Given an X509V3 extension tag, this function returns the corresponding
 * extension validator.
 */

static cfx_validator *cfx_find(
    int tag)
{
    unsigned int i;

    for (i = 0; i < sizeof(xvalidators) / sizeof(cfx_validator); i++)
    {
        if (xvalidators[i].tag == tag)
            return (&xvalidators[i]);
    }
    return (NULL);
}

static cf_validator validators[] = {
    {NULL, 0, 0},               /* filename handled already */
    {&cf_get_subject, CF_FIELD_SUBJECT, 1},
    {&cf_get_issuer, CF_FIELD_ISSUER, 1},
    {&cf_get_sn, CF_FIELD_SN, 1},
    {&cf_get_from, CF_FIELD_FROM, 1},
    {&cf_get_to, CF_FIELD_TO, 1},
    {&cf_get_sig, CF_FIELD_SIGNATURE, 1},
    {NULL, 0, 0}                /* terminator */
};

cert_fields *cert2fields(
    char *fname,
    char *fullname,
    object_type typ,
    X509 **xp,
    err_code *stap,
    int *x509stap)
{
    const unsigned char *udat;
    cfx_validator *cfx;
    const X509V3_EXT_METHOD *meth;
    X509_EXTENSION *ex;
    X509_CINF *ci;
    cert_fields *cf;
    unsigned int ui;
    BIO *bcert = NULL;
    X509 *x = NULL;
    void *exts;
    char *res;
    int freex;
    int x509sta;
    int excnt;
    int need;
    int i;

    if (stap == NULL || x509stap == NULL)
        return (NULL);
    *x509stap = 1;
    if (xp == NULL)
    {
        *stap = ERR_SCM_INVALARG;
        return (NULL);
    }
    // case 1: filenames are given
    if (fname != NULL && fname[0] != 0 && fullname != NULL && fullname[0] != 0)
    {
        *xp = NULL;
        freex = 1;
        cf = (cert_fields *) calloc(1, sizeof(cert_fields));
        if (cf == NULL)
        {
            *stap = ERR_SCM_NOMEM;
            return (NULL);
        }
        cf->fields[CF_FIELD_FILENAME] = strdup(fname);
        if (cf->fields[CF_FIELD_FILENAME] == NULL)
        {
            *stap = ERR_SCM_NOMEM;
            return (NULL);
        }
        // open the file
        bcert = BIO_new(BIO_s_file());
        if (bcert == NULL)
        {
            *stap = ERR_SCM_NOMEM;
            return (NULL);
        }
        x509sta = BIO_read_filename(bcert, fullname);
        if (x509sta <= 0)
        {
            BIO_free(bcert);
            freecf(cf);
            *stap = ERR_SCM_X509;
            *x509stap = x509sta;
            return (NULL);
        }
        // read the cert based on the input type
        if (typ < OT_PEM_OFFSET)
            x = d2i_X509_bio(bcert, NULL);
        else
            x = PEM_read_bio_X509_AUX(bcert, NULL, NULL, NULL);
        BIO_free(bcert);
        if (x == NULL)
        {
            freecf(cf);
            *stap = ERR_SCM_BADCERT;
            return (NULL);
        }
    }
    // case 2: x is given
    else
    {
        x = *xp;
        if (x == NULL)
        {
            *stap = ERR_SCM_INVALARG;
            return (NULL);
        }
        freex = 0;
        cf = (cert_fields *) calloc(1, sizeof(cert_fields));
        if (cf == NULL)
        {
            *stap = ERR_SCM_NOMEM;
            return (NULL);
        }
        if (fname != NULL)
        {
            cf->fields[CF_FIELD_FILENAME] = strdup(fname);
            if (cf->fields[CF_FIELD_FILENAME] == NULL)
            {
                *stap = ERR_SCM_NOMEM;
                return (NULL);
            }
        }
    }
    // get all the non-extension fields; if a field cannot be gotten and its
    // needed, that is a fatal error. Note that these validators are assumed
    // to be in linear order
    for (i = 1; i < CF_NFIELDS; i++)
    {
        if (validators[i].get_func == NULL)
            break;
        res = (*validators[i].get_func)(x, stap, x509stap);
        if (res == NULL && validators[i].need > 0)
        {
            if (freex)
            {
                X509_free(x);
                x = NULL;
            }
            freecf(cf);
            if (*stap == 0)
                *stap = ERR_SCM_X509;
            return (NULL);
        }
        cf->fields[i] = res;
    }
    // get the extension fields
    excnt = X509_get_ext_count(x);
    ci = x->cert_info;
    for (i = 0; i < excnt; i++)
    {
        ex = sk_X509_EXTENSION_value(ci->extensions, i);
        if (ex == NULL)
            continue;
        meth = X509V3_EXT_get(ex);
        if (meth == NULL)
            continue;
        udat = ex->value->data;
        if (meth->it)
            exts = ASN1_item_d2i(NULL, &udat, ex->value->length,
                                 ASN1_ITEM_ptr(meth->it));
        else
            exts = meth->d2i(NULL, &udat, ex->value->length);
        if (exts == NULL)
            continue;
        *stap = 0;
        *x509stap = 0;
        need = 0;
        cfx = cfx_find(meth->ext_nid);
        if (cfx != NULL && cfx->get_func != NULL)
        {
            need = cfx->need;
            if (cfx->raw == 0)
                (*cfx->get_func)(meth, exts, cf, stap, x509stap);
            else
                (*cfx->get_func)(meth, ex, cf, stap, x509stap);
        }
        if (meth->it)
            ASN1_item_free(exts, ASN1_ITEM_ptr(meth->it));
        else
            meth->ext_free(exts);
        if (*stap != 0 && need > 0)
            break;
    }
    // check that all needed extension fields are present
    for (ui = 0; ui < sizeof(xvalidators) / sizeof(cfx_validator); ui++)
    {
        if (xvalidators[ui].need > 0 &&
            cf->fields[xvalidators[ui].fieldno] == NULL)
        {
            LOG(LOG_ERR, "Missing CF_FIELD %d", xvalidators[ui].fieldno);
            *stap = ERR_SCM_MISSEXT;
            break;
        }
    }
    if (*stap != 0)
    {
        freecf(cf);
        cf = NULL;
        if (freex)
        {
            X509_free(x);
            x = NULL;
        }
    }
    *xp = x;
    return (cf);
}

char *X509_to_ski(
    X509 *x,
    err_code *stap,
    int *x509stap)
{
    const X509V3_EXT_METHOD *meth;
    const unsigned char *udat;
    cfx_validator *cfx;
    X509_EXTENSION *ex;
    X509_CINF *ci;
    cert_fields *cf;
    void *exts;
    char *dptr;
    int excnt;
    int i;

    if (stap == NULL || x509stap == NULL)
        return (NULL);
    dptr = NULL;
    *x509stap = 1;
    if (x == NULL)
    {
        *stap = ERR_SCM_INVALARG;
        return (NULL);
    }
    cf = (cert_fields *) calloc(1, sizeof(cert_fields));
    if (cf == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        return (NULL);
    }
    // get the extension fields
    excnt = X509_get_ext_count(x);
    ci = x->cert_info;
    for (i = 0; i < excnt; i++)
    {
        ex = sk_X509_EXTENSION_value(ci->extensions, i);
        if (ex == NULL)
            continue;
        meth = X509V3_EXT_get(ex);
        if (meth == NULL)
            continue;
        if (meth->ext_nid != NID_subject_key_identifier)
            continue;
        udat = ex->value->data;
        if (meth->it)
            exts = ASN1_item_d2i(NULL, &udat, ex->value->length,
                                 ASN1_ITEM_ptr(meth->it));
        else
            exts = meth->d2i(NULL, &udat, ex->value->length);
        if (exts == NULL)
            continue;
        *stap = 0;
        *x509stap = 0;
        cfx = cfx_find(meth->ext_nid);
        if (cfx != NULL && cfx->get_func != NULL)
        {
            if (cfx->raw == 0)
                (*cfx->get_func)(meth, exts, cf, stap, x509stap);
            else
                (*cfx->get_func)(meth, ex, cf, stap, x509stap);
        }
        if (meth->it)
            ASN1_item_free(exts, ASN1_ITEM_ptr(meth->it));
        else
            meth->ext_free(exts);
        if (cf->fields[CF_FIELD_SKI] != NULL)
        {
            *x509stap = 0;
            break;
        }
    }
    if (*stap != 0)
    {
        freecf(cf);
        cf = NULL;
    }
    if (cf != NULL && cf->fields[CF_FIELD_SKI] != NULL)
        dptr = strdup(cf->fields[CF_FIELD_SKI]);
    freecf(cf);
    return (dptr);
}

static crf_get crf_get_issuer;
char *
crf_get_issuer(
    X509_CRL *x,
    err_code *stap,
    int *crlstap)
{
    char *ptr;
    char *dptr;

    if (x == NULL || stap == NULL || crlstap == NULL)
        return (NULL);
    ptr = X509_NAME_oneline(X509_CRL_get_issuer(x), NULL, 0);
    if (ptr == NULL)
    {
        *stap = ERR_SCM_NOISSUER;
        return (NULL);
    }
    dptr = strdup(ptr);
    OPENSSL_free(ptr);
    if (dptr == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        return (NULL);
    }
    return (dptr);
}

static crf_get crf_get_last;
char *
crf_get_last(
    X509_CRL *x,
    err_code *stap,
    int *crlstap)
{
    ASN1_GENERALIZEDTIME *nb4;
    unsigned char *bef = NULL;
    char *dptr;
    int asn1sta;

    nb4 = X509_CRL_get_lastUpdate(x);
    if (nb4 == NULL)
    {
        *stap = ERR_SCM_NONB4;
        return (NULL);
    }
    asn1sta = ASN1_STRING_to_UTF8(&bef, (ASN1_STRING *) nb4);
    if (asn1sta < 0)            /* error */
    {
        *crlstap = asn1sta;
        *stap = ERR_SCM_CRL;
        return (NULL);
    }
    if (bef == NULL || asn1sta == 0)    /* null string */
    {
        *stap = ERR_SCM_NONB4;
        return (NULL);
    }
    dptr = ASNTimeToDBTime((char *)bef, stap, 0);
    OPENSSL_free(bef);
    if (dptr == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        return (NULL);
    }
    return (dptr);
}

static crf_get crf_get_next;
char *
crf_get_next(
    X509_CRL *x,
    err_code *stap,
    int *crlstap)
{
    ASN1_GENERALIZEDTIME *naf;
    unsigned char *aft = NULL;
    char *dptr;
    int asn1sta;

    naf = X509_CRL_get_nextUpdate(x);
    if (naf == NULL)
    {
        *stap = ERR_SCM_NONAF;
        return (NULL);
    }
    asn1sta = ASN1_STRING_to_UTF8(&aft, (ASN1_STRING *) naf);
    if (asn1sta < 0)            /* error */
    {
        *crlstap = asn1sta;
        *stap = ERR_SCM_CRL;
        return (NULL);
    }
    if (aft == NULL || asn1sta == 0)    /* null string */
    {
        *stap = ERR_SCM_NONAF;
        return (NULL);
    }
    dptr = ASNTimeToDBTime((char *)aft, stap, 0);
    OPENSSL_free(aft);
    if (dptr == NULL)
    {
        // stap already set by ASNTimeToDBTime
        return (NULL);
    }
    return (dptr);
}

static crf_get crf_get_sig;
char *
crf_get_sig(
    X509_CRL *x,
    err_code *stap,
    int *crlstap)
{
    (void)crlstap;

    char *dptr;

    if (x->signature == NULL || x->signature->data == NULL ||
        x->signature->length <= 0)
    {
        *stap = ERR_SCM_NOSIG;
        return (NULL);
    }
    dptr = hexify(x->signature->length, (void *)(x->signature->data), 0);
    if (dptr == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        return (NULL);
    }
    return (dptr);
}

static crf_validator crvalidators[] = {
    {NULL, 0, 0},               /* filename handled already */
    {&crf_get_issuer, CRF_FIELD_ISSUER, 1},
    {&crf_get_last, CRF_FIELD_LAST, 0},
    {&crf_get_next, CRF_FIELD_NEXT, 1},
    {&crf_get_sig, CRF_FIELD_SIGNATURE, 1},
    {NULL, 0, 0}                /* terminator */
};

static crfx_get crf_get_crlno;
void
crf_get_crlno(
    const X509V3_EXT_METHOD *meth,
    void *exts,
    crl_fields *cf,
    err_code *stap,
    int *crlstap)
{
    ASN1_INTEGER *crlno_a1 = (ASN1_INTEGER *)exts;
    BIGNUM *crlno_bn;
    char *ptr;
    char *dptr;

    if (stap == NULL)
        return;
    if (meth == NULL || exts == NULL || cf == NULL || crlstap == NULL)
    {
        *stap = ERR_SCM_INVALARG;
        return;
    }

    crlno_bn = ASN1_INTEGER_to_BN(crlno_a1, NULL);
    if (crlno_bn == NULL)
    {
        *stap = ERR_SCM_BIGNUMERR;
        return;
    }

    ptr = BN_bn2hex(crlno_bn);
    if (ptr == NULL)
    {
        BN_free(crlno_bn);
        *stap = ERR_SCM_BIGNUMERR;
        return;
    }
    BN_free(crlno_bn);

    dptr = malloc(2 + strlen(ptr) + 1);
    if (dptr == NULL)
    {
        OPENSSL_free(ptr);
        *stap = ERR_SCM_NOMEM;
        return;
    }

    xsnprintf(dptr, 2 + strlen(ptr) + 1, "^x%s", ptr);

    OPENSSL_free(ptr);

    cf->fields[CRF_FIELD_SN] = dptr;
}

static crfx_get crf_get_aki;
void
crf_get_aki(
    const X509V3_EXT_METHOD *meth,
    void *exts,
    crl_fields *cf,
    err_code *stap,
    int *crlstap)
{
    AUTHORITY_KEYID *aki;
    char *ptr;
    char *dptr;

    if (stap == NULL)
        return;
    if (meth == NULL || exts == NULL || cf == NULL || crlstap == NULL)
    {
        *stap = ERR_SCM_INVALARG;
        return;
    }
    aki = (AUTHORITY_KEYID *) exts;
    if (aki->keyid == NULL)
    {
        *stap = ERR_SCM_XPROFILE;
        return;
    }
    ptr = hex_to_string(aki->keyid->data, aki->keyid->length);
    if (ptr == NULL)
    {
        *stap = ERR_SCM_INVALEXT;
        return;
    }
    dptr = strdup(ptr);
    OPENSSL_free(ptr);
    if (dptr == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        return;
    }
    cf->fields[CRF_FIELD_AKI] = dptr;
}

static crfx_validator crxvalidators[] = {
    {&crf_get_crlno, CRF_FIELD_SN, NID_crl_number, 1},
    {&crf_get_aki, CRF_FIELD_AKI, NID_authority_key_identifier, 1}
};

/*
 * Given an X509V3 extension tag, this function returns the corresponding
 * extension validator.
 */

static crfx_validator *crfx_find(
    int tag)
{
    unsigned int i;

    for (i = 0; i < sizeof(crxvalidators) / sizeof(crfx_validator); i++)
    {
        if (crxvalidators[i].tag == tag)
            return (&crxvalidators[i]);
    }
    return (NULL);
}

crl_fields *crl2fields(
    char *fname,
    char *fullname,
    object_type typ,
    X509_CRL **xp,
    err_code *stap,
    int *crlstap,
    void *oidtestp)
{
    const unsigned char *udat;
    crfx_validator *cfx;
    STACK_OF(X509_REVOKED) *rev;
    const X509V3_EXT_METHOD *meth;
    X509_EXTENSION *ex;
    X509_REVOKED *r;
    unsigned char *tov;
    crl_fields *cf;
    unsigned int ui;
    ASN1_INTEGER *a1;
    X509_CRL *x = NULL;
    BIGNUM *bn;
    BIO *bcert = NULL;
    void *exts;
    char *res;
    int freex;
    int crlsta;
    int excnt;
    err_code snerr;
    int need;
    int i;
    unsigned int snlen; // snlen (total num of serials) >= cf->snlen (num of valid serials)

    if (stap == NULL || crlstap == NULL)
        return (NULL);
    *crlstap = 1;
    if (xp == NULL)
    {
        *stap = ERR_SCM_INVALARG;
        return (NULL);
    }
    // case 1: filenames are given
    if (fname != NULL && fname[0] != 0 && fullname != NULL && fullname[0] != 0)
    {
        *xp = NULL;
        freex = 1;
        cf = (crl_fields *) calloc(1, sizeof(crl_fields));
        if (cf == NULL)
        {
            *stap = ERR_SCM_NOMEM;
            return (NULL);
        }
        cf->fields[CRF_FIELD_FILENAME] = strdup(fname);
        if (cf->fields[CRF_FIELD_FILENAME] == NULL)
        {
            *stap = ERR_SCM_NOMEM;
            return (NULL);
        }
        // open the file
        bcert = BIO_new(BIO_s_file());
        if (bcert == NULL)
        {
            *stap = ERR_SCM_NOMEM;
            return (NULL);
        }
        crlsta = BIO_read_filename(bcert, fullname);
        if (crlsta <= 0)
        {
            BIO_free(bcert);
            freecrf(cf);
            *stap = ERR_SCM_CRL;
            *crlstap = crlsta;
            return (NULL);
        }
        // read the CRL based on the input type
        if (typ < OT_PEM_OFFSET)
            x = d2i_X509_CRL_bio(bcert, NULL);
        else
            x = PEM_read_bio_X509_CRL(bcert, NULL, NULL, NULL);
        if (x == NULL)
        {
            BIO_free(bcert);
            freecrf(cf);
            *stap = ERR_SCM_BADCRL;
            return (NULL);
        }
    }
    // case 2: x is given
    else
    {
        x = *xp;
        if (x == NULL)
        {
            *stap = ERR_SCM_INVALARG;
            return (NULL);
        }
        freex = 0;
        cf = (crl_fields *) calloc(1, sizeof(crl_fields));
        if (cf == NULL)
        {
            *stap = ERR_SCM_NOMEM;
            return (NULL);
        }
    }
    // get all the non-extension fields; if a field cannot be gotten and its
    // needed, that is a fatal error. Note also that these are assumed to be
    // in linear order.
    for (i = 1; i < CRF_NFIELDS; i++)
    {
        if (crvalidators[i].get_func == NULL)
            break;
        res = (*crvalidators[i].get_func)(x, stap, crlstap);
        if (res == NULL && crvalidators[i].need > 0)
        {
            if (freex)
                X509_CRL_free(x);
            if (bcert != NULL)
                BIO_free(bcert);
            freecrf(cf);
            if (*stap == 0)
                *stap = ERR_SCM_CRL;
            return (NULL);
        }
        cf->fields[i] = res;
    }
    // get flags, snlen and snlist; note that snlen is the count of
    // serials, not bytes
    cf->flags = 0;
    if (X509_cmp_current_time(X509_CRL_get_nextUpdate(x)) < 0)
        cf->flags |= SCM_FLAG_STALECRL;
    rev = X509_CRL_get_REVOKED(x);
    if (rev == NULL)
        snlen = 0;
    else
        snlen = sk_X509_REVOKED_num(rev);
    cf->snlen = 0;
    snerr = 0;
    if (snlen > 0)
    {
        cf->snlist = (void *)calloc(snlen, SER_NUM_MAX_SZ);
        if (cf->snlist == NULL)
        {
            *stap = ERR_SCM_NOMEM;
            return (NULL);
        }
        tov = (uint8_t *)(cf->snlist);
        for (ui = 0; ui < snlen; ui++)
        {
            r = sk_X509_REVOKED_value(rev, ui);
            if (r == NULL)
            {
                snerr = ERR_SCM_NOSN;
                break;
            }
            a1 = r->serialNumber;
            if (a1 == NULL)
            {
                snerr = ERR_SCM_NOSN;
                break;
            }
            bn = ASN1_INTEGER_to_BN(a1, NULL);
            if (bn == NULL)
            {
                snerr = ERR_SCM_BIGNUMERR;
                break;
            }
            int numbytes = BN_num_bytes(bn);
            if (BN_num_bits(bn) < SER_NUM_MAX_SZ * 8 && !BN_is_zero(bn) &&
                !BN_is_negative(bn))
            {
                memset(tov, 0, SER_NUM_MAX_SZ - numbytes);
                tov += SER_NUM_MAX_SZ - numbytes;
                BN_bn2bin(bn, tov);
                tov += numbytes;
                BN_free(bn);
                ++cf->snlen;
            }
            else
            {
                // ignore the invalid serial number
                BN_free(bn);
            }
        }
    }
    if (snerr < 0)
    {
        if (bcert != NULL)
            BIO_free(bcert);
        freecrf(cf);
        if (freex)
        {
            X509_CRL_free(x);
            x = NULL;
        }
        *stap = snerr;
        return (NULL);
    }
    // get the extension fields
    struct goodoid *goodoids = (struct goodoid *)oidtestp;
    excnt = X509_CRL_get_ext_count(x);
    if (excnt != 2)
    {
        LOG(LOG_ERR, "Wrong number of CRL extensions");
        *stap = ERR_SCM_INVALEXT;
    }
    else
    {
        int did = 0;
        for (i = 0; i < excnt; i++)
        {
            ex = sk_X509_EXTENSION_value(x->crl->extensions, i);
            if (ex == NULL)
                continue;
            struct goodoid *goodoidp;
            for (goodoidp = goodoids; goodoidp->lth > 0; goodoidp++)
            {
                if (goodoidp->lth == ex->object->length &&
                    !memcmp(ex->object->data, goodoidp->oid, goodoidp->lth))
                    break;
            }
            if (!goodoidp->lth)
            {
                LOG(LOG_ERR, "Invalid CRL extension [%d]", i);
                *stap = ERR_SCM_INVALEXT;
                break;
            }
            else
                did += (goodoidp - goodoids) + 1;
            meth = X509V3_EXT_get(ex);
            if (meth == NULL)
                continue;
            udat = ex->value->data;
            if (meth->it)
                exts = ASN1_item_d2i(NULL, &udat, ex->value->length,
                                     ASN1_ITEM_ptr(meth->it));
            else
                exts = meth->d2i(NULL, &udat, ex->value->length);
            if (exts == NULL)
                continue;
            *stap = 0;
            *crlstap = 0;
            need = 0;
            cfx = crfx_find(meth->ext_nid);
            if (cfx != NULL && cfx->get_func != NULL)
            {
                need = cfx->need;
                (*cfx->get_func)(meth, exts, cf, stap, crlstap);
            }
            if (meth->it)
                ASN1_item_free(exts, ASN1_ITEM_ptr(meth->it));
            else
                meth->ext_free(exts);
            if (*stap != 0 && need > 0)
                break;
        }
        if (*stap == 0 && did != 3)
        {
            *stap = ERR_SCM_INVALEXT;
            LOG(LOG_ERR, "Duplicate extensions");
        }
    }
    // check that all needed extension fields are present
    if (!*stap)
    {
        for (ui = 0; ui < sizeof(crxvalidators) / sizeof(crfx_validator); ui++)
        {
            if (crxvalidators[ui].need > 0 &&
                cf->fields[crxvalidators[ui].fieldno] == NULL)
            {
                /** @bug shouldn't xvalidators be crxvalidators? */
                LOG(LOG_ERR, "Missing CF_FIELD %d",
                        xvalidators[ui].fieldno);
                *stap = ERR_SCM_MISSEXT;
                break;
            }
        }
    }
    if (bcert != NULL)
        BIO_free(bcert);
    if (*stap != 0)
    {
        freecrf(cf);
        if (freex)
        {
            X509_CRL_free(x);
            x = NULL;
        }
        cf = NULL;
    }
    *xp = x;
    return (cf);
}


/*************************************************************
 * This is a minimal modification of                         *
 * x509v3_cache_extensions() found in crypt/X509v3/v3_purp.c *
 * what it does is to load up the X509_st struct so one can  *
 * check extensions in the unsigned long flags within that   *
 * structure rather than recursively calling in the ASN.1    *
 * elements until one finds the correct NID/OID              *
 ************************************************************/

static void x509v3_load_extensions(
    X509 * x)
{
    BASIC_CONSTRAINTS *bs;
    PROXY_CERT_INFO_EXTENSION *pci;
    ASN1_BIT_STRING *usage;
    ASN1_BIT_STRING *ns;
    EXTENDED_KEY_USAGE *extusage;
    X509_EXTENSION *ex;
    int i;

    /*
     * Passing int*, instead of NULL, to the 3rd and 4th parameters of
     * X509_get_ext_d2i() allows it to return the extensions we are looking
     * for, instead of returning NULL, in certain error cases.  Also, it may
     * return error codes via those pointers.
     */
    int crit = INT_MIN;

    if (x->ex_flags & EXFLAG_SET)
        return;
#ifndef OPENSSL_NO_SHA
    X509_digest(x, EVP_sha1(), x->sha1_hash, NULL);
#endif
    /*
     * Does subject name match issuer ?
     */
    if (!X509_NAME_cmp(X509_get_subject_name(x), X509_get_issuer_name(x)))
        x->ex_flags |= EXFLAG_SS;
    /*
     * V1 should mean no extensions ...
     */
    if (!X509_get_version(x))
        x->ex_flags |= EXFLAG_V1;
    /*
     * Handle basic constraints
     */
    if ((bs = X509_get_ext_d2i(x, NID_basic_constraints, &crit, NULL)))
    {
        if (bs->ca)
            x->ex_flags |= EXFLAG_CA;
        if (bs->pathlen)
        {
            if ((bs->pathlen->type == V_ASN1_NEG_INTEGER) || !bs->ca)
            {
                x->ex_flags |= EXFLAG_INVALID;
                x->ex_pathlen = 0;
            }
            else
            {
                x->ex_pathlen = ASN1_INTEGER_get(bs->pathlen);
            }
        }
        else
        {
            x->ex_pathlen = -1;
        }

        BASIC_CONSTRAINTS_free(bs);
        x->ex_flags |= EXFLAG_BCONS;
    }

    /*
     * Handle proxy certificates
     */
    if ((pci = X509_get_ext_d2i(x, NID_proxyCertInfo, &crit, NULL)))
    {
        if (x->ex_flags & EXFLAG_CA ||
            X509_get_ext_by_NID(x, NID_subject_alt_name, 0) >= 0
            || X509_get_ext_by_NID(x, NID_issuer_alt_name, 0) >= 0)
        {
            x->ex_flags |= EXFLAG_INVALID;
        }
        if (pci->pcPathLengthConstraint)
        {
            x->ex_pcpathlen = ASN1_INTEGER_get(pci->pcPathLengthConstraint);
        }
        else
        {
            x->ex_pcpathlen = -1;
        }
        PROXY_CERT_INFO_EXTENSION_free(pci);
        x->ex_flags |= EXFLAG_PROXY;
    }

    /*
     * Handle key usage
     */
    if ((usage = X509_get_ext_d2i(x, NID_key_usage, &crit, NULL)))
    {
        if (usage->length > 0)
        {
            x->ex_kusage = usage->data[0];
            if (usage->length > 1)
                x->ex_kusage |= usage->data[1] << 8;
        }
        else
        {
            x->ex_kusage = 0;
        }
        x->ex_flags |= EXFLAG_KUSAGE;
        ASN1_BIT_STRING_free(usage);
    }
    x->ex_xkusage = 0;
    if ((extusage = X509_get_ext_d2i(x, NID_ext_key_usage, &crit, NULL)))
    {
        x->ex_flags |= EXFLAG_XKUSAGE;
        for (i = 0; i < sk_ASN1_OBJECT_num(extusage); i++)
        {
            switch (OBJ_obj2nid(sk_ASN1_OBJECT_value(extusage, i)))
            {
            case NID_server_auth:
                x->ex_xkusage |= XKU_SSL_SERVER;
                break;

            case NID_client_auth:
                x->ex_xkusage |= XKU_SSL_CLIENT;
                break;

            case NID_email_protect:
                x->ex_xkusage |= XKU_SMIME;
                break;

            case NID_code_sign:
                x->ex_xkusage |= XKU_CODE_SIGN;
                break;

            case NID_ms_sgc:
            case NID_ns_sgc:
                x->ex_xkusage |= XKU_SGC;
                break;

            case NID_OCSP_sign:
                x->ex_xkusage |= XKU_OCSP_SIGN;
                break;

            case NID_time_stamp:
                x->ex_xkusage |= XKU_TIMESTAMP;
                break;

            case NID_dvcs:
                x->ex_xkusage |= XKU_DVCS;
                break;
            }
        }
        sk_ASN1_OBJECT_pop_free(extusage, ASN1_OBJECT_free);
    }

    if ((ns = X509_get_ext_d2i(x, NID_netscape_cert_type, &crit, NULL)))
    {
        if (ns->length > 0)
            x->ex_nscert = ns->data[0];
        else
            x->ex_nscert = 0;
        x->ex_flags |= EXFLAG_NSCERT;
        ASN1_BIT_STRING_free(ns);
    }

    x->skid = X509_get_ext_d2i(x, NID_subject_key_identifier, &crit, NULL);
    x->akid = X509_get_ext_d2i(x, NID_authority_key_identifier, &crit, NULL);
    x->crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, &crit, NULL);
    x->rfc3779_addr = X509_get_ext_d2i(x, NID_sbgp_ipAddrBlock, &crit, NULL);
    x->rfc3779_asid =
        X509_get_ext_d2i(x, NID_sbgp_autonomousSysNum, &crit, NULL);

    for (i = 0; i < X509_get_ext_count(x); i++)
    {
        ex = X509_get_ext(x, i);
        if (!X509_EXTENSION_get_critical(ex))
            continue;
        if (!X509_supported_extension(ex))
        {
            x->ex_flags |= EXFLAG_CRITICAL;
            break;
        }
    }
    x->ex_flags |= EXFLAG_SET;
}

/*
 * Check certificate flags against the manifest certificate type
 */

static err_code
rescert_flags_chk(
    X509 *x,
    int ct)
{
    LOG(LOG_DEBUG, "rescert_flags_chk(x=%p, ct=%d)", x, ct);

    static const unsigned long ta_flags =
        (EXFLAG_SET | EXFLAG_SS | EXFLAG_CA | EXFLAG_KUSAGE | EXFLAG_BCONS);
    static const unsigned long ta_kusage =
        (KU_KEY_CERT_SIGN | KU_CRL_SIGN);
    static const unsigned long ca_flags =
        (EXFLAG_SET | EXFLAG_CA | EXFLAG_KUSAGE | EXFLAG_BCONS);
    static const unsigned long ca_kusage =
        (KU_KEY_CERT_SIGN | KU_CRL_SIGN);
    static const unsigned long ee_flags =
        (EXFLAG_SET | EXFLAG_KUSAGE);
    static const unsigned long ee_kusage =
        (KU_DIGITAL_SIGNATURE);
    int cert_type;
    err_code ret = 0;

    if ((x->ex_flags == ta_flags) && (x->ex_kusage == ta_kusage))
        cert_type = TA_CERT;
    else if ((x->ex_flags == ca_flags) && (x->ex_kusage == ca_kusage))
        cert_type = CA_CERT;
    else if ((x->ex_flags == ee_flags) && (x->ex_kusage == ee_kusage))
        cert_type = EE_CERT;
    else
        cert_type = UN_CERT;
    if (ct == cert_type)
    {
        goto done;
    }
    else
    {
        if (x->ex_flags & EXFLAG_CRITICAL)
        {
            LOG(LOG_ERR,
                    "OpenSSL reports an unsupported critical extension "
                    "in an X.509 certificate.  Please ensure that OpenSSL "
                    "was compiled with RFC 3779 support.");
        }
        LOG(LOG_ERR, "certificate's flags are not appropriate for its type");
        ret = ERR_SCM_BADFLAGS;
        goto done;
    }

done:
    LOG(LOG_DEBUG, "rescert_flags_chk() returning %s: %s",
        err2name(ret), err2string(ret));
    return ret;
}

/*************************************************************
 * int rescert_version_chk(X509 *)                           *
 *                                                           *
 *  we require v3 certs (which is value 2)                   *
 ************************************************************/

static err_code
rescert_version_chk(
    X509 *x)
{
    LOG(LOG_DEBUG, "rescert_version_chk(x=%p)", x);

    long l;
    err_code ret = 0;

    l = X509_get_version(x);
    /*
     * returns the value which is 2 to denote version 3
     */

    LOG(LOG_DEBUG, "certificate version: %lu", l + 1);
    if (l != 2)                 /* see above: value of 2 means v3 */
    {
        LOG(LOG_ERR, "bad certificate version (must be v3, is %lu)", l+1);
        ret = ERR_SCM_BADCERTVERS;
        goto done;
    }

done:
    LOG(LOG_DEBUG, "rescert_version_chk() returning %s: %s",
        err2name(ret), err2string(ret));
    return ret;
}


/*************************************************************
 * rescert_basic_constraints_chk(X509 *, int)                *
 *                                                           *
 *  Basic Constraints - critical MUST be present             *
 *    path length constraint MUST NOT be present             *
 *                                                           *
 * Whereas the Huston rescert sidr draft states that         *
 * basic Constraints must be present and must be marked crit *
 * RFC 2459 states that it SHOULD NOT be present for EE cert *
 *                                                           *
 * the certs that APNIC et al have been making have the      *
 * extension present but not marked critical in EE certs     *
 * sooo...                                                   *
 *    If it's a CA cert then it MUST be present and MUST     *
 *    be critical. If it's an EE cert then it MUST be        *
 *    present MUST NOT have the cA flag set and we don't     *
 *    care if it's marked critical or not. awaiting word     *
 *    back from better sources than I if this is correct.    *
 *                                                           *
 ************************************************************/

static err_code
rescert_basic_constraints_chk(
    X509 *x,
    int ct)
{
    int i;
    int basic_flag = 0;
    int ex_nid;
    err_code ret = 0;
    X509_EXTENSION *ex = NULL;
    BASIC_CONSTRAINTS *bs = NULL;

    /*
     * test the basic_constraints based against either an CA_CERT (cert
     * authority), EE_CERT (end entity), or TA_CERT (trust anchor) as definied
     * in the X509 Profile for resource certificates.
     */
    switch (ct)
    {

    case UN_CERT:
        /*
         * getting here means we couldn't figure it out above..
         */
        LOG(LOG_ERR, "couldn't determine cert_type to test against");
        return (ERR_SCM_INVALARG);
        break;

    case CA_CERT:
    case TA_CERT:
        /*
         * Basic Constraints MUST be present, MUST be critical, cA boolean has
         * to be set for CAs
         */
        for (i = 0; i < X509_get_ext_count(x); i++)
        {
            ex = X509_get_ext(x, i);
            ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

            if (ex_nid == NID_basic_constraints)
            {
                basic_flag++;

                if (!X509_EXTENSION_get_critical(ex))
                {
                    LOG(LOG_ERR,
                            "[basic_const] CA_CERT: basic_constraints NOT critical!");
                    ret = ERR_SCM_NCEXT;
                    goto skip;
                }

                bs = X509V3_EXT_d2i(ex);
                if (!bs)
                {
                    LOG(LOG_ERR, "Couldn't parse basic_constraints");
                    ret = ERR_SCM_BADEXT;
                    goto skip;
                }
                if (!(bs->ca))
                {
                    LOG(LOG_ERR,
                            "[basic_const] testing for CA_CERT: cA boolean NOT set");
                    ret = ERR_SCM_NOTCA;
                    goto skip;
                }

                if (bs->pathlen)
                {
                    LOG(LOG_ERR,
                            "[basic_const] basic constraints pathlen present "
                            "- profile violation");
                    ret = ERR_SCM_BADPATHLEN;
                    goto skip;
                }

                BASIC_CONSTRAINTS_free(bs);
                bs = NULL;
            }
        }
        if (basic_flag == 0)
        {
            LOG(LOG_ERR, "[basic_const] basic_constraints not present");
            return (ERR_SCM_NOBC);
        }
        else if (basic_flag > 1)
        {
            LOG(LOG_ERR, "[basic_const] multiple instances of extension");
            return (ERR_SCM_DUPBC);
        }
        else
        {
            return (0);
        }
        break;                  /* should never get to break */

    case EE_CERT:
        /*
         * Basic Constraints MUST NOT be present
         */
        for (i = 0; i < X509_get_ext_count(x); i++)
        {
            ex = X509_get_ext(x, i);
            ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));
            if (ex_nid == NID_basic_constraints)
                return (ERR_SCM_BCPRES);
        }
        return 0;
        break;
    }
  skip:
    LOG(LOG_DEBUG, "[basic_const] jump to return...");
    if (bs)
        BASIC_CONSTRAINTS_free(bs);
    return (ret);
}

/**=============================================================================
 * @brief Check a cert's SKI.
 *
 * Subject Key Identifier - non-critical MUST be present
 *
 * We don't do anything with the cert_type as this is true
 * of EE, CA, and TA certs in the resrouce cert profile
 *
 * @param x (struct X509*)
 *
 * @return 0 on success<br />negative integer on failure
 -----------------------------------------------------------------------------*/
static err_code
rescert_ski_chk(
    X509 *x,
    struct Certificate *certp)
{

    int ski_flag = 0;
    int i;
    int ex_nid;
    err_code ret = 0;
    X509_EXTENSION *ex = NULL;

    for (i = 0; i < X509_get_ext_count(x); i++)
    {
        ex = X509_get_ext(x, i);
        ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

        if (ex_nid == NID_subject_key_identifier)
        {
            ski_flag++;
            if (X509_EXTENSION_get_critical(ex))
            {
                LOG(LOG_ERR, "SKI marked as critical, profile violation");
                ret = ERR_SCM_CEXT;
                goto skip;
            }
        }
    }
    if (ski_flag == 0)
    {
        LOG(LOG_ERR, "[ski] ski extension missing");
        return (ERR_SCM_NOSKI);
    }
    else if (ski_flag > 1)
    {
        LOG(LOG_ERR, "[ski] multiple instances of ski extension");
        return (ERR_SCM_DUPSKI);
    }

    /*
     * check ski hash
     */
    struct Extension *extp = find_extension(&certp->toBeSigned.extensions,
                                            id_subjectKeyIdentifier, false);
    if (extp)
    {
        uchar hash[40];
        int key_info_len =
            vsize_casn(&certp->toBeSigned.
                       subjectPublicKeyInfo.subjectPublicKey);
        if (key_info_len <= 0)
            return ERR_SCM_INVALSKI;
        uchar *pub_key_infp = calloc(1, key_info_len + 4);
        if (!pub_key_infp)
            return ERR_SCM_NOMEM;
        if (read_casn(&certp->toBeSigned.subjectPublicKeyInfo.subjectPublicKey,
                      pub_key_infp) != key_info_len)
        {
            free(pub_key_infp);
            return ERR_SCM_INVALSKI;
        }
        // Subject public key info is a BIT STRING, so the first octet is the
        // number of unused bits.  We require it to be zero, but skip it.
        if (pub_key_infp[0] != 0)
        {
            free(pub_key_infp);
            return ERR_SCM_UNSUPPUBKEY;
        }
        gen_hash(&pub_key_infp[1], key_info_len - 1, hash, CRYPT_ALGO_SHA1);
        free(pub_key_infp);
        pub_key_infp = NULL;

        // Compare 160-bit SHA-1 hash of subject public key info to SKI.
        uchar ski_data[20];
        int hash_len = vsize_casn(&extp->extnValue.subjectKeyIdentifier);
        if (hash_len != 160 / 8)
        {
            LOG(LOG_ERR, "wrong ski length: %d instead of 160 bits",
                    8 * hash_len);
            return ERR_SCM_INVALSKI;
        }
        int ski_len =
            read_casn(&extp->extnValue.subjectKeyIdentifier, ski_data);
        if (ski_len != 160 / 8)
        {
            LOG(LOG_ERR, "failed to read ski");
            return ERR_SCM_INVALSKI;
        }
        if (memcmp(ski_data, hash, hash_len))
        {
            LOG(LOG_ERR, "SKI does not match Subject Public Key Info");
            return ERR_SCM_INVALSKI;
        }
    }
    else
    {
        LOG(LOG_ERR, "could not find ski extension for cert");
        return (ERR_SCM_INVALSKI);
    }

    return (0);
  skip:
    LOG(LOG_DEBUG, "[ski]jump to return...");
    return (ret);
}

/*************************************************************
 * rescert_aki_chk(X509 *, int)                              *
 *                                                           *
 *  Authority Key Identifier - non-critical MUST be present  *
 *      in CA and EE, optional in TAs.                       *
 *    keyIdentifier - MUST be present                        *
 *    authorityCertIssuer - MUST NOT be present              *
 *    authorityCertSerialNumber - MUST NOT be present        *
 *                                                           *
 ************************************************************/

static err_code
rescert_aki_chk(
    X509 *x,
    int ct)
{
    int aki_flag = 0;
    int i;
    int ex_nid;
    err_code ret = 0;
    X509_EXTENSION *ex = NULL;
    AUTHORITY_KEYID *akid = NULL;

    for (i = 0; i < X509_get_ext_count(x); i++)
    {
        ex = X509_get_ext(x, i);
        ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

        if (ex_nid == NID_authority_key_identifier)
        {
            aki_flag++;

            if (X509_EXTENSION_get_critical(ex))
            {
                LOG(LOG_ERR, "[aki] critical, profile violation");
                ret = ERR_SCM_CEXT;
                goto skip;
            }

            akid = X509V3_EXT_d2i(ex);
            if (!akid)
            {
                LOG(LOG_ERR, "Failed to parse AKI");
                ret = ERR_SCM_BADEXT;
                goto skip;
            }

            /*
             * Key Identifier sub field MUST be present in any certs that have
             * an AKI
             */
            if (!akid->keyid)
            {
                LOG(LOG_ERR, "[aki] key identifier sub field not present");
                ret = ERR_SCM_NOAKI;
                goto skip;
            }

            if (akid->issuer)
            {
                LOG(LOG_ERR,
                        "[aki_chk] authorityCertIssuer is present = violation");
                ret = ERR_SCM_ACI;
                goto skip;
            }

            if (akid->serial)
            {
                LOG(LOG_ERR,
                        "[aki_chk] authorityCertSerialNumber is present = violation");
                ret = ERR_SCM_ACSN;
                goto skip;
            }

            // http://tools.ietf.org/html/draft-ietf-sidr-res-certs-22#section-4.8.3
            if (akid->keyid->length != 160 / 8)
            {
                LOG(LOG_ERR,
                        "[aki] key identifier has %d bytes instead of %d",
                        akid->keyid->length, 160 / 8);
                ret = ERR_SCM_INVALAKI;
                goto skip;
            }
        }
    }

    if (akid)
    {
        AUTHORITY_KEYID_free(akid);
        akid = NULL;
    }

    if (aki_flag == 0 && ct != TA_CERT)
    {
        LOG(LOG_ERR, "[aki_chk] missing AKI extension");
        return (ERR_SCM_NOAKI);
    }
    else if (aki_flag > 1)
    {
        LOG(LOG_ERR, "[aki_chk] duplicate AKI extensions");
        return (ERR_SCM_DUPAKI);
    }
    else
    {
        return (0);
    }

  skip:
    LOG(LOG_DEBUG, "[aki]jump to return...");
    if (akid)
        AUTHORITY_KEYID_free(akid);
    return (ret);
}

/*************************************************************
 * rescert_key_usage_chk(X509 *)                             *
 *                                                           *
 *  Key Usage - critical - MUST be present                   *
 *    TA|CA - keyCertSign and CRLSign only                   *
 *    EE - digitalSignature only                             *
 *                                                           *
 ************************************************************/

static err_code
rescert_key_usage_chk(
    X509 *x)
{
    int kusage_flag = 0;
    int i;
    int ex_nid;
    err_code ret = 0;
    X509_EXTENSION *ex = NULL;

    for (i = 0; i < X509_get_ext_count(x); i++)
    {
        ex = X509_get_ext(x, i);
        ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

        if (ex_nid == NID_key_usage)
        {
            kusage_flag++;
            if (!X509_EXTENSION_get_critical(ex))
            {
                LOG(LOG_ERR, "[kusage] not marked critical, violation");
                ret = ERR_SCM_NCEXT;
                goto skip;
            }

            /*
             * I don't like that I'm depending upon other OpenSSL components
             * for the populating of a parent structure for testing this, but
             * running out of time and there's no KEY_USAGE_st and I don't
             * have the time to parse the ASN1_BIT_STRING (probably trivial
             * but don't know it yet...). Check asn1/asn1.h for struct
             * asn1_string_st, x509v3/v3_bitst.c, and get the ASN1_BIT_STRING
             * via usage=X509_get_ext_d2i(x, NID_key_usage, NULL, NULL) if we
             * end up doing this correctly.
             */
            /*
             * TODO: possibly replace this function. Notes from Charlie Oct 2,
             * 2011: In the file /home/gardiner/cwgrpki/trunk/proto/myssl.c
             * around line 1271 there is code to check the usage bits.  It
             * requires the variable "ct", which is available in
             * rescerrt_profile_chk, and a pointer to the extension, which
             * should be obtainable from the Certificate structure in
             * rescert_profile_chk().
             */
        }
    }

    if (kusage_flag == 0)
    {
        LOG(LOG_ERR, "[key_usage] missing Key Usage extension");
        return (ERR_SCM_NOKUSAGE);
    }
    else if (kusage_flag > 1)
    {
        LOG(LOG_ERR, "[key_usage] multiple key_usage extensions");
        return (ERR_SCM_DUPKUSAGE);
    }
    else
    {
        return (0);
    }

  skip:
    LOG(LOG_DEBUG, "[key_usage] jump to...");
    return (ret);
}

/** Checks based on http://tools.ietf.org/html/rfc6487#section-4.8.5 */
static err_code
rescert_extended_key_usage_chk(
    X509 *x,
    int ct)
{
    int i;
    int eku_flag = 0;
    int ex_nid;
    err_code ret = 0;
    X509_EXTENSION *ex = NULL;

    for (i = 0; i < X509_get_ext_count(x); ++i)
    {
        ex = X509_get_ext(x, i);
        ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

        if (ex_nid == NID_ext_key_usage)
        {
            ++eku_flag;
            if (X509_EXTENSION_get_critical(ex))
            {
                LOG(LOG_ERR,
                        "[extended_key_usage] marked critical, violation");
                ret = ERR_SCM_CEXT;
                goto skip;
            }
        }
    }

    if (ct == TA_CERT || ct == CA_CERT)
    {
        if (eku_flag)
        {
            LOG(LOG_ERR, "[extended_key_usage] EKU present in CA cert");
            ret = ERR_SCM_EKU;
            goto skip;
        }
    }
    else if (ct == EE_CERT)
    {
        // XXX: this should check if it's a CMS EE cert, other EE
        // certs are allowed to have EKU
        if (eku_flag)
        {
            LOG(LOG_ERR,
                    "[extended_key_usage] EKU present in CMS EE cert");
            ret = ERR_SCM_EKU;
            goto skip;
        }
    }

  skip:
    LOG(LOG_DEBUG, "[extended_key_usage] jump to return...");
    return ret;
}

/*************************************************************
 * rescert_crldp_chk(X509 *, int)                            *
 *                                                           *
 *  CRL Distribution Points - non-crit -                     *
 *  MUST be present unless the CA is self-signed (TA) in     *
 *  which case it MUST be omitted.                           *
 *                                                           *
 *  CRLissuer MUST be omitted                                *
 *  reasons MUST be omitted                                  *
 *                                                           *
 ************************************************************/

static err_code
rescert_crldp_chk(
    X509 *x,
    int ct)
{
    int crldp_flag = 0;
    int uri_flag = 0;
    int rsync_uri_flag = 0;
    int ncrldp = 0;
    int j;
    int i;
    int ex_nid;
    err_code ret = 0;
    STACK_OF(DIST_POINT) * crldp = NULL;
    DIST_POINT *dist_st = NULL;
    X509_EXTENSION *ex = NULL;
    GENERAL_NAME *gen_name = NULL;
    int crit = INT_MIN;
    int idx = INT_MIN;

    for (i = 0; i < X509_get_ext_count(x); i++)
    {
        ex = X509_get_ext(x, i);
        ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));
        if (ex_nid == NID_crl_distribution_points)
        {
            crldp_flag++;
            if (X509_EXTENSION_get_critical(ex))
            {
                LOG(LOG_ERR, "[crldp] marked critical, violation");
                ret = ERR_SCM_CEXT;
                goto skip;
            }
        }
    }

    if (ct == TA_CERT)
    {
        /*
         * CRLDP must be omitted if TA
         */
        ret = crldp_flag ? ERR_SCM_CRLDPTA : 0;
        goto skip;
    }

    if (crldp_flag == 0)
    {
        LOG(LOG_ERR, "[crldp] missing crldp extension");
        return (ERR_SCM_NOCRLDP);
    }
    else if (crldp_flag > 1)
    {
        LOG(LOG_ERR, "[crldp] duplicate crldp extensions");
        ret = ERR_SCM_DUPCRLDP;
        goto skip;
    }
    /*
     * we should be here if NID_crl_distribution_points was found, and it was
     * not marked critical
     */
    crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, &crit, &idx);
    if (!crldp)
    {
        LOG(LOG_ERR, "[crldp] could not retrieve crldp extension");
        return (ERR_SCM_NOCRLDP);
    }
    ncrldp = sk_DIST_POINT_num(crldp);
    for (j = 0; j < ncrldp; j++)
    {
        dist_st = sk_DIST_POINT_value(crldp, j);
        if (dist_st->reasons || dist_st->CRLissuer || !dist_st->distpoint
            || dist_st->distpoint->type != 0)
        {
            LOG(LOG_ERR, "[crldp] incorrect crldp sub fields");
            ret = ERR_SCM_CRLDPSF;
            goto skip;
        }
        for (i = 0; i < sk_GENERAL_NAME_num(dist_st->distpoint->name.fullname);
             i++)
        {
            gen_name =
                sk_GENERAL_NAME_value(dist_st->distpoint->name.fullname, i);
            if (!gen_name)
            {
                LOG(LOG_ERR,
                        "[crldp] error retrieving distribution point name");
                ret = ERR_SCM_CRLDPNM;
                goto skip;
            }
            /*
             * all of the general names must be of type URI
             */
            if (gen_name->type != GEN_URI)
            {
                LOG(LOG_ERR,
                        "[crldp] general name of non GEN_URI type found");
                ret = ERR_SCM_BADCRLDP;
                goto skip;
            }
            uri_flag++;
            if (!strncasecmp
                ((char *)gen_name->d.uniformResourceIdentifier->data,
                 RSYNC_PREFIX, RSYNC_PREFIX_LEN))
            {
                /*
                 * printf("uri: %s\n",
                 * gen_name->d.uniformResourceIdentifier->data);
                 */
                rsync_uri_flag++;
            }
        }
    }
    if (uri_flag == 0)
    {
        LOG(LOG_ERR, "[crldp] no general name of type URI");
        ret = ERR_SCM_CRLDPNM;
        goto skip;
    }
    else if (rsync_uri_flag == 0)
    {
        LOG(LOG_ERR,
                "[crldp] no general name of type URI with RSYNC access method");
        ret = ERR_SCM_CRLDPNMRS;
        goto skip;
    }
    else
    {
        if (crldp)
        {
            sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
            crldp = NULL;
        }
        return (0);
    }
  skip:
    LOG(LOG_DEBUG, "[crldp] jump to return...");
    if (crldp)
        sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    return (ret);
}

/*************************************************************
 * rescert_aia_chk(X509 *, int)                              *
 *                                                           *
 *  Authority Information Access - non-crit - MUST           *
 *     be present, except in the case of TAs where it        *
 *     MUST be omitted (but this is checked elsewhere).      *
 *                                                           *
 ************************************************************/

static err_code
rescert_aia_chk(
    X509 *x,
    int ct)
{
    int info_flag = 0;
    int uri_flag = 0;
    int i;
    int ex_nid;
    err_code ret = 0;
    int aia_oid_len;
    AUTHORITY_INFO_ACCESS *aia = NULL;
    ACCESS_DESCRIPTION *adesc = NULL;
    X509_EXTENSION *ex;
    static const unsigned char aia_oid[] =
        { 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x2 };
    int crit = INT_MIN;
    int idx = INT_MIN;

    aia_oid_len = sizeof(aia_oid);

    for (i = 0; i < X509_get_ext_count(x); i++)
    {
        ex = X509_get_ext(x, i);
        ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

        if (ex_nid == NID_info_access)
        {
            info_flag++;

            if (X509_EXTENSION_get_critical(ex))
            {
                LOG(LOG_ERR, "[aia] marked critical, violation");
                ret = ERR_SCM_CEXT;
                goto skip;
            }

        }
    }

    if (ct == TA_CERT)
    {
        if (info_flag == 0)
        {
            ret = 0;
        }
        else
        {
            LOG(LOG_ERR, "[aia] AIA present in TA cert");
            ret = ERR_SCM_AIATA;
        }

        goto skip;
    }

    if (info_flag == 0)
    {
        LOG(LOG_ERR, "[aia] missing aia extension");
        return (ERR_SCM_NOAIA);
    }
    else if (info_flag > 1)
    {
        LOG(LOG_ERR, "[aia] multiple aia extensions");
        return (ERR_SCM_DUPAIA);
    }

    /*
     * we should be here if NID_info_access was found, it was not marked
     * critical, and there was only one instance of it.
     *
     * Rob's code from rcynic shows how to get the URI out of the aia... so
     * lifting his teachings.  Though he should be using strncasecmp rather
     * than strncmp as I don't think there are any specifications requiring
     * the URI to be case sensitive.
     */

    aia = X509_get_ext_d2i(x, NID_info_access, &crit, &idx);
    if (!aia)
    {
        LOG(LOG_ERR, "[aia] could not retrieve aia extension");
        return (ERR_SCM_NOAIA);
    }

    for (i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++)
    {
        adesc = sk_ACCESS_DESCRIPTION_value(aia, i);
        if (!adesc)
        {
            LOG(LOG_ERR, "[aia] error retrieving access description");
            ret = ERR_SCM_NOAIA;
            goto skip;
        }
        /*
         * URI form of object identification in AIA
         */
        if (adesc->location->type != GEN_URI)
        {
            LOG(LOG_ERR, "[aia] access type of non GEN_URI found");
            ret = ERR_SCM_BADAIA;
            goto skip;
        }

        if ((adesc->method->length == aia_oid_len) &&
            (!memcmp(adesc->method->data, aia_oid, aia_oid_len)) &&
            (!strncasecmp
             ((char *)adesc->location->d.uniformResourceIdentifier->data,
              RSYNC_PREFIX, RSYNC_PREFIX_LEN)))
        {
            uri_flag++;
        }
    }

    if (uri_flag == 0)
    {
        LOG(LOG_ERR, "[aia] no aia name of type URI rsync");
        ret = ERR_SCM_BADAIA;
        goto skip;
    }
    else
    {
        ret = 0;
        goto skip;
    }

  skip:
    LOG(LOG_DEBUG, "[aia] jump to return...");
    if (aia)
        sk_ACCESS_DESCRIPTION_pop_free(aia, ACCESS_DESCRIPTION_free);
    return (ret);
}


/**=============================================================================
 * @brief Check if Certificate is CA or EE.
 *
 * Note:  TA not checked here.
 * Note:  Validity of CA, EE flags not checked here.
 * Note:  This really should check the cA boolean, but this works because of
 *        http://tools.ietf.org/html/rfc6487#section-4.8.1 provided that
 *        somewhere else checks that the cA boolean is set for CA certs.
 *
 * @param certp (struct Certificate*)
 * @retval ret int type of the Certificate<br />-1 for error
 -----------------------------------------------------------------------------*/
static int get_cert_type(
    struct Certificate *certp)
{
    struct Extension *extp = NULL;

    extp =
        (struct Extension *)member_casn(&certp->toBeSigned.extensions.self, 0);
    for (; extp; extp = (struct Extension *)next_of(&extp->self))
    {
        /** @bug error code ignored without explanation */
        if (!diff_objid(&extp->extnID, id_basicConstraints))
            return CA_CERT;
    }

    return EE_CERT;
}


/**=============================================================================
 * @brief Check correctness of SIA.
 *
 * @param certp (struct Certificate*)
 * @retval ret 0 on success<br />a negative integer on failure
 -----------------------------------------------------------------------------*/
static err_code
rescert_sia_chk(
    struct Certificate *certp)
{
    int count = -1;
    int type = -1;
    struct Extension *extp = NULL;

    extp = get_extension(certp, id_pe_subjectInfoAccess, &count);
    if (count == 0)
    {
        LOG(LOG_ERR, "no SIA found");
        return ERR_SCM_NOSIA;
    }
    if (count > 1)
    {
        LOG(LOG_ERR, "multiple SIA found");
        return ERR_SCM_DUPSIA;
    }
    if (extp == NULL)
    {
        LOG(LOG_ERR, "error reading SIA");
        return ERR_SCM_BADSIA;
    }

    uchar crit_bool = 0;
    int size = INT_MIN;
    size = read_casn(&extp->critical, &crit_bool);
    if (size && crit_bool)
    {
        LOG(LOG_ERR, "critical bit set for SIA");
        return ERR_SCM_CEXT;
    }

    // Need different checks for a CA vs EE Cert
    type = get_cert_type(certp);
    if (type != CA_CERT && type != EE_CERT)
    {
        LOG(LOG_ERR, "could not read certificate type; or unknown type");
        return ERR_SCM_NOBC;
    }

    struct AccessDescription *adp;
    struct SubjectInfoAccess *siap;
    siap = &extp->extnValue.subjectInfoAccess;
    adp = (struct AccessDescription *)member_casn(&siap->self, 0);
    if (type == CA_CERT)
    {
        int found_uri_repo_rsync = 0;
        int found_uri_mft_rsync = 0;
        uchar *uri_repo = 0;
        uchar *uri_mft = 0;
        for (; adp; adp = (struct AccessDescription *)next_of(&adp->self))
        {
            /** @bug error code ignored without explanation */
            if (!diff_objid(&adp->accessMethod, id_ad_caRepository) &&
                size_casn((struct casn *)&adp->accessLocation.url))
            {
                size = vsize_casn((struct casn *)&adp->accessLocation.url);
                uri_repo = calloc(1, size + 1);
                if (!uri_repo)
                    return ERR_SCM_NOMEM;
                read_casn((struct casn *)&adp->accessLocation.url, uri_repo);
                if (!strncasecmp((char *)uri_repo, RSYNC_PREFIX, 8))
                    found_uri_repo_rsync = 1;
                free(uri_repo);
                uri_repo = NULL;
            }
            /** @bug error code ignored without explanation */
            else if (!diff_objid(&adp->accessMethod, id_ad_rpkiManifest) &&
                size_casn((struct casn *)&adp->accessLocation.url))
            {
                size = vsize_casn((struct casn *)&adp->accessLocation.url);
                uri_mft = calloc(1, size + 1);
                if (!uri_mft)
                    return ERR_SCM_NOMEM;
                read_casn((struct casn *)&adp->accessLocation.url, uri_mft);
                if (!strncasecmp((char *)uri_mft, RSYNC_PREFIX, 8))
                    found_uri_mft_rsync = 1;
                free(uri_mft);
                uri_mft = NULL;
            }
        }

        if (!found_uri_repo_rsync)
        {
            LOG(LOG_ERR, "did not find rsync uri for repository for SIA");
            return ERR_SCM_BADSIA;
        }
        if (!found_uri_mft_rsync)
        {
            LOG(LOG_ERR, "did not find rsync uri for manifest for SIA");
            return ERR_SCM_BADSIA;
        }
    }
    else
    {                           // (type == EE_CERT)
        int found_uri_obj_rsync = 0;
        uchar *uri_obj = 0;
        for (; adp; adp = (struct AccessDescription *)next_of(&adp->self))
        {
            /** @bug error code ignored without explanation */
            if (!diff_objid(&adp->accessMethod, id_ad_signedObject)  || !diff_objid(&adp->accessMethod, id_ad_rpkiNotify) )
            {
                if (size_casn((struct casn *)&adp->accessLocation.url))
                {
                    size = vsize_casn((struct casn *)&adp->accessLocation.url);
                    uri_obj = calloc(1, size + 1);
                    if (!uri_obj)
                        return ERR_SCM_NOMEM;
                    read_casn((struct casn *)&adp->accessLocation.url, uri_obj);
                    if (!strncasecmp((char *)uri_obj, RSYNC_PREFIX, 8))
                        found_uri_obj_rsync = 1;
                    free(uri_obj);
                    uri_obj = NULL;
                }
            }
            else
            {
                LOG(LOG_ERR,
                        "in EE-cert SIA, found accessMethod != id-ad-signedObject");
                return ERR_SCM_BADSIA;
            }
        }

        if (!found_uri_obj_rsync)
        {
            LOG(LOG_ERR,
                    "did not find rsync uri for signedObject for SIA");
            return ERR_SCM_BADSIA;
        }
    }

    return 0;
}

/*************************************************************
 * rescert_cert_policy_chk(X509 *)                           *
 *                                                           *
 *  Certificate Policies - critical - MUST be present        *
 *    PolicyQualifiers - MUST NOT be used in this profile    *
 *    OID Policy Identifier value: "1.3.6.1.5.5.7.14.2"      *
 *                                                           *
 ************************************************************/

static err_code
rescert_cert_policy_chk(
    X509 *x)
{
    int policy_flag = 0;
    int i;
    int ex_nid;
    err_code ret = 0;
    int len;
    X509_EXTENSION *ex = NULL;
    CERTIFICATEPOLICIES *ex_cpols = NULL;
    POLICYINFO *policy;
    POLICYQUALINFO *policy_qual;
    int policy_qual_nid;
    char policy_id_str[32];
    char *oid_policy_id = "1.3.6.1.5.5.7.14.2"; // http://tools.ietf.org/html/rfc6484#section-1.2
    int policy_id_len = strlen(oid_policy_id);
    int crit = INT_MIN;
    int idx = INT_MIN;

    memset(policy_id_str, '\0', sizeof(policy_id_str));

    for (i = 0; i < X509_get_ext_count(x); i++)
    {
        ex = X509_get_ext(x, i);
        ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

        if (ex_nid == NID_certificate_policies)
        {
            policy_flag++;
            if (!X509_EXTENSION_get_critical(ex))
            {
                LOG(LOG_ERR, "[policy] not marked as critical");
                ret = ERR_SCM_NCEXT;
                goto skip;
            }
        }
    }
    if (policy_flag == 0)
    {
        LOG(LOG_ERR, "[policy] policy extension missing");
        ret = ERR_SCM_NOPOLICY;
        goto skip;
    }
    else if (policy_flag > 1)
    {
        LOG(LOG_ERR, "[policy] multiple instances of policy extension");
        ret = ERR_SCM_DUPPOLICY;
        goto skip;
    }

    /*
     * we should be here if policy_flag == 1, it was marked critical, and
     * there was only one instance of it.
     */
    ex_cpols = X509_get_ext_d2i(x, NID_certificate_policies, &crit, &idx);
    if (!ex_cpols)
    {
        LOG(LOG_ERR, "[policy] policies present but could not retrieve");
        ret = ERR_SCM_NOPOLICY;
        goto skip;
    }

    if (sk_POLICYINFO_num(ex_cpols) != 1)
    {
        LOG(LOG_ERR, "[policy] incorrect number of policies");
        ret = ERR_SCM_DUPPOLICY;
        goto skip;
    }

    policy = sk_POLICYINFO_value(ex_cpols, 0);
    if (!policy)
    {
        LOG(LOG_ERR, "[policy] could not retrieve policyinfo");
        ret = ERR_SCM_NOPOLICY;
        goto skip;
    }

    len =
        i2t_ASN1_OBJECT(policy_id_str, sizeof(policy_id_str),
                        policy->policyid);

    if ((len != policy_id_len) || (strcmp(policy_id_str, oid_policy_id)))
    {
        LOG(LOG_ERR, "len: %d value: %s\n", len, policy_id_str);
        LOG(LOG_ERR, "[policy] OID Policy Identifier value incorrect");
        ret = ERR_SCM_BADOID;
        goto skip;
    }

    if (policy->qualifiers)
    {
        if (sk_POLICYQUALINFO_num(policy->qualifiers) > 1)
        {
            LOG(LOG_ERR, "[policy] too many policy qualifiers");
            ret = ERR_SCM_POLICYQ;
            goto skip;
        }


        policy_qual = sk_POLICYQUALINFO_value(policy->qualifiers, 0);
        policy_qual_nid = OBJ_obj2nid(policy_qual->pqualid);

        if (policy_qual_nid != NID_id_qt_cps)
        {
            LOG(LOG_ERR, "[policy] invalid policy qualifier ID, only CPS is allowed");
            ret = ERR_SCM_POLICYQ;
            goto skip;
        }
    }

  skip:
    LOG(LOG_DEBUG, "[policy] jump to return...");

    if (ex_cpols)
        sk_POLICYINFO_pop_free(ex_cpols, POLICYINFO_free);

    return (ret);
}

/*************************************************************
 * rescert_ip_resources_chk(struct Certificate *)            *
 *                                                           *
 * Returns 0 if there is no IP extension, 1 if there is      *
 * exactly one extension that is critical, or a negative     *
 * error code.                                               *
 *                                                           *
 ************************************************************/
static err_code
rescert_ip_resources_chk(
    struct Certificate *certp,
    int ct)
{
    int ext_count = 0;
    struct Extension *extp = get_extension(certp, id_pe_ipAddrBlock,
                                           &ext_count);
    if (!extp || !ext_count)
    {
        LOG(LOG_DEBUG, "no IP extension found");
        return 0;
    }
    else if (ext_count > 1)
    {
        LOG(LOG_ERR, "multiple IP extensions found");
        return ERR_SCM_DUPIP;
    }

    if (!vsize_casn(&extp->self))
    {
        LOG(LOG_ERR, "IP extension is empty");
        return ERR_SCM_INVALEXT;
    }

    int size = vsize_casn((struct casn *)&extp->critical);
    uchar critical = 0;
    if (size != 1)
    {
        if (size < 1)
        {
            LOG(LOG_ERR, "IP extension not marked critical");
            return ERR_SCM_NCEXT;
        }
        else
        {
            LOG(LOG_ERR,
                    "IP extension critical flag is longer than one byte");
            return ERR_SCM_INVALEXT;
        }
    }
    else
    {
        read_casn(&extp->critical, &critical);
        if (!critical)
        {
            LOG(LOG_ERR, "IP extension not marked critical");
            return ERR_SCM_NCEXT;
        }
    }

    bool have_contents = false;
    struct IpAddrBlock *ipAddrBlock = &extp->extnValue.ipAddressBlock;
    struct IPAddressFamilyA *ipAddrFamA;
    for (ipAddrFamA = (struct IPAddressFamilyA *)member_casn(&ipAddrBlock->self, 0);
        ipAddrFamA != NULL;
        ipAddrFamA = (struct IPAddressFamilyA *)next_of(&ipAddrFamA->self))
    {
        if (vsize_casn(&ipAddrFamA->addressFamily) != 2)
        {
            LOG(LOG_ERR, "IP address family contains a SAFI");
            return ERR_SCM_INVALFAM;
        }

        if (size_casn(&ipAddrFamA->ipAddressChoice.inherit) ||
            num_items(&ipAddrFamA->ipAddressChoice.addressesOrRanges.self) > 0)
        {
            have_contents = true;
        }

        if (size_casn(&ipAddrFamA->ipAddressChoice.inherit) &&
            ct == TA_CERT)
        {
            LOG(LOG_ERR, "IP resources marked inherit in a trust anchor");
            return ERR_SCM_TAINHERIT;
        }
    }

    if (!have_contents)
    {
        LOG(LOG_ERR, "IP extension has no resources and is not marked inherit");
        return ERR_SCM_NOIPADDR;
    }

    return 1;
}


/*************************************************************
 * rescert_as_resources_chk(struct Certificate *)            *
 *                                                           *
 * @return 0 on success with no AS info, 1 on success with   *
 *           AS info, a negative integer on failure          *
 *                                                           *
 ************************************************************/
/*
 * openssl not checking AS number canonicity as of 1.0.0.d even tho it
 * contains Rob Austein's patch from Dec, 20101
 */
static err_code
rescert_as_resources_chk(
    struct Certificate *certp,
    int ct)
{
    int ext_count = 0;
    struct Extension *extp = get_extension(certp, id_pe_autonomousSysNum,
                                           &ext_count);
    if (!extp || !ext_count)
    {
        LOG(LOG_DEBUG, "no AS extension found");
        return 0;
    }
    else if (ext_count > 1)
    {
        LOG(LOG_ERR, "multiple AS extensions found");
        return ERR_SCM_DUPAS;
    }

    if (!vsize_casn(&extp->self))
    {
        LOG(LOG_ERR, "AS extension is empty");
        return ERR_SCM_INVALEXT;
    }

    int size = vsize_casn((struct casn *)&extp->critical);
    uchar critical = 0;
    if (size != 1)
    {
        if (size < 1)
        {
            LOG(LOG_ERR, "AS extension not marked critical");
            return ERR_SCM_NCEXT;
        }
        else
        {
            LOG(LOG_ERR,
                    "AS extension critical flag is longer than one byte");
            return ERR_SCM_INVALEXT;
        }
    }
    else
    {
        read_casn(&extp->critical, &critical);
        if (!critical)
        {
            LOG(LOG_ERR, "AS extension not marked critical");
            return ERR_SCM_NCEXT;
        }
    }

    if (size_casn((struct casn *)&extp->extnValue.autonomousSysNum.rdi.self))
    {
        LOG(LOG_ERR, "AS extension contains non-NULL rdi element");
        return ERR_SCM_BADASRDI;
    }

    struct ASIdentifierChoiceA *asidcap =
        &extp->extnValue.autonomousSysNum.asnum;
    if (size_casn(&asidcap->inherit))
    {
        if (ct == TA_CERT)
        {
            LOG(LOG_ERR, "AS resources marked inherit in a trust anchor");
            return ERR_SCM_TAINHERIT;
        }

        LOG(LOG_DEBUG, "AS resources marked as inherit");
        return 1;
    }
    if (num_items(&asidcap->asNumbersOrRanges.self) <= 0)
    {
        LOG(LOG_ERR, "AS NumbersOrRanges is empty, or error reading it");
        return ERR_SCM_BADASRANGE;
    }
    return 1;
}

/*************************************************************
 * rescert_ip_asnum_chk(X509 *, struct Certificate *)        *
 *                                                           *
 *  IP Resources, AS Resources - critical - MUST have one    *
 *   of these or both.                                       *
 *                                                           *
 * Note that OpenSSL now include Rob's code for 3779         *
 * extensions and it looks like the check and load them      *
 * correctly. All we should need to do is to make sure that  *
 * this function makes sure one or the other (ip or as res)  *
 * is present and then call simple routines to make sure     *
 * there are not multiple instances of the same extension    *
 * and that the extension(s) present are marked critical.    *
 ************************************************************/
static err_code
rescert_ip_asnum_chk(
    X509 *x,
    struct Certificate *certp,
    int ct)
{
    err_code have_ip_resources;
    err_code have_as_resources;
    ASIdentifiers *as_ext;
    IPAddrBlocks *ip_ext;

    have_ip_resources = rescert_ip_resources_chk(certp, ct);
    if (have_ip_resources < 0)
        return (have_ip_resources);

    have_as_resources = rescert_as_resources_chk(certp, ct);
    if (have_as_resources < 0)
        return (have_as_resources);

    if (!have_ip_resources && !have_as_resources)
    {
        LOG(LOG_ERR, "cert has neither IP resources, nor AS resources");
        return (ERR_SCM_NOIPAS);
    }

    if (have_ip_resources)
    {
        ip_ext = X509_get_ext_d2i(x, NID_sbgp_ipAddrBlock, NULL, NULL);

        if (!ip_ext)
        {
            LOG(LOG_ERR, "couldn't get IP extension");
            return (ERR_SCM_INVALIPB);
        }

        if (!v3_addr_is_canonical(ip_ext))
        {
            LOG(LOG_ERR, "cert IP resources are not in canonical form");
            sk_IPAddressFamily_free(ip_ext);
            return (ERR_SCM_INVALIPB);
        }

        sk_IPAddressFamily_free(ip_ext);
    }

    if (have_as_resources)
    {
        as_ext = X509_get_ext_d2i(x, NID_sbgp_autonomousSysNum, NULL, NULL);

        if (!as_ext)
        {
            LOG(LOG_ERR, "couldn't get AS extension");
            return (ERR_SCM_BADASRANGE);
        }

        if (!v3_asid_is_canonical(as_ext))
        {
            LOG(LOG_ERR, "cert AS resources are not in canonical form");
            ASIdentifiers_free(as_ext);
            return (ERR_SCM_BADASRANGE);
        }

        ASIdentifiers_free(as_ext);
    }

    return (0);
}


/*
 * from x509v3/v3_purp.c
 */
static int res_nid_cmp(
    int *a,
    int *b)
{
    return *a - *b;
}

/*
 * this function is a minimal change to OpenSSL's X509_supported_extension()
 * function from crypto/x509v3/v3_purp.c
 *
 * The modifications are a change in the supported nids array to match the
 * Resource Certificate Profile sepecification
 *
 * This function is used to catch extensions that might be marked critical
 * that we were not expecting. You should only pass this criticals.
 *
 * Criticals in Resource Certificate Profile: Basic Constraints Key Usage
 * Certificate Policies (NOT Subject Alt Name, which is going to be removed
 * anyway in the future from this profile) IP Resources AS Resources
 */

static err_code
rescert_crit_ext_chk(
    X509_EXTENSION *ex)
{
    /*
     * This table is a list of the NIDs of supported extensions: that is those
     * which are used by the verify process. If an extension is critical and
     * doesn't appear in this list then the verify process will normally
     * reject the certificate. The list must be kept in numerical order
     * because it will be searched using bsearch.
     */

    static int supported_nids[] = {
        NID_key_usage,          /* 83 */
        NID_basic_constraints,  /* 87 */
        NID_certificate_policies,       /* 89 */
        NID_sbgp_ipAddrBlock,   /* 290 */
        NID_sbgp_autonomousSysNum,      /* 291 */
    };

    int ex_nid;

    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

    if (ex_nid == NID_undef)
        return ERR_SCM_BADEXT;

    if (bsearch((char *)&ex_nid, (char *)supported_nids,
                sizeof(supported_nids) / sizeof(int), sizeof(int),
                (int (*)(const void *, const void *))res_nid_cmp))
        return (0);
    return (ERR_SCM_BADEXT);
}

/*************************************************************
 * rescert_criticals_present_chk(X509 *)                     *
 *                                                           *
 *  This iterates through what we expect to be critical      *
 *  extensions present in TA,CA,EE certs. If there is a crit *
 *  extension that we don't recognize it fails. If there is  *
 *  an extension that we expect to see as a crit or if an    *
 *  extension that is supposed to be marked crit is marked   *
 *  non-crit it fails.                                       *
 *                                                           *
 * currently stubbed... don't know if *we* should be doing   *
 * this check or if it should be done elsewhere.             *
 ************************************************************/

static err_code
rescert_criticals_chk(
    X509 *x)
{
    err_code ret = 0;
    int i;
    X509_EXTENSION *ex = NULL;

    for (i = 0; i < X509_get_ext_count(x); i++)
    {
        ex = X509_get_ext(x, i);
        if (!X509_EXTENSION_get_critical(ex))
            continue;
        ret = rescert_crit_ext_chk(ex);
        if (ret < 0)
            return (ret);
    }

    return (0);
}


/**=============================================================================
 * @brief Check that issuer/subject name contains specified items.
 *
 * Note:  This function is not generalizable to other RDNSequence items because
 *   it imposes stricter limits on quantities of items contained.  It is
 *   written specifically to handle Issuer/Subject RDNs.
 *
 * @param rdnseqp (struct RDNSequence*)
 * @return 0 on success<br />a negative integer on failure
 -----------------------------------------------------------------------------*/
static err_code
rescert_name_chk(
    struct RDNSequence *rdnseqp)
{
    int sequence_length,
        sequence_idx;
    int set_length,
        set_idx;
    bool commonName = false;
    bool serialNumber = false;
    if ((sequence_length = num_items(&rdnseqp->self)) > 2)
    {
        // RFC 6487 limits the total number of attributes, not the sequence
        // length explicitly
        LOG(LOG_ERR, "RDNSeq contains >2 RelativeDistinguishedName");
        return ERR_SCM_UNSPECIFIED;
    }
    for (sequence_idx = 0; sequence_idx < sequence_length; ++sequence_idx)
    {
        struct RelativeDistinguishedName *rdnp =
            (struct RelativeDistinguishedName *)member_casn(&rdnseqp->self,
                                                            sequence_idx);
        if ((set_length = num_items(&rdnp->self)) > 2)
        {
            // RFC 6487 limits the total number of attributes, not the set
            // length explicitly
            LOG(LOG_ERR,
                    "RelativeDistinguishedName contains >2 Attribute Value Assertions");
            return ERR_SCM_UNSPECIFIED;
        }
        for (set_idx = 0; set_idx < set_length; ++set_idx)
        {
            struct AttributeValueAssertion *avap =
                (struct AttributeValueAssertion *)member_casn(&rdnp->self,
                                                              set_idx);
            /** @bug error code ignored without explanation */
            if (!diff_objid(&avap->objid, id_commonName))
            {
                if (commonName)
                {
                    LOG(LOG_ERR, "multiple CommonNames");
                    return ERR_SCM_UNSPECIFIED;
                }
                commonName = true;
                if (vsize_casn(&avap->value.commonName.printableString) <= 0)
                {
                    if (strict_profile_checks)
                    {
                        LOG(LOG_ERR, "CommonName not printableString");
                        return ERR_SCM_UNSPECIFIED;
                    }
                    else
                    {
                        LOG(LOG_WARNING, "CommonName not printableString");
                    }
                }
            }
            /** @bug error code ignored without explanation */
            else if (!diff_objid(&avap->objid, id_serialNumber))
            {
                if (serialNumber)
                {
                    LOG(LOG_ERR, "multiple SerialNumbers");
                    return ERR_SCM_UNSPECIFIED;
                }
                serialNumber = true;
            }
            else
            {
                LOG(LOG_ERR,
                        "AttributeValueAssertion contains an OID that is neither id_commonName nor id_serialNumber");
                return ERR_SCM_UNSPECIFIED;
            }
        }
    }

    if (!commonName)
    {
        LOG(LOG_ERR, "no CommonName present");
        return ERR_SCM_UNSPECIFIED;
    }

    return 0;
}


/**=============================================================================
 * @brief Check that certs list the proper signature algorithms and parameters.
 *
 * This applies to the:
 * - inner signature algorithm
 * - outer signature algorithm
 * - public key signature algorithm and parameters
 *
 * @param certp (struct Certificate*)
 * @retval ret 0 on success<br />a negative integer on failure
 -----------------------------------------------------------------------------*/
static err_code
rescert_sig_algs_chk(
    struct Certificate *certp)
{
    int length = vsize_objid(&certp->algorithm.algorithm);
    if (length <= 0)
    {
        LOG(LOG_ERR, "length of outer sig alg oid <= 0");
        return ERR_SCM_BADALG;
    }
    char *outer_sig_alg_oidp = calloc(1, length + 1);
    if (!outer_sig_alg_oidp)
        /** @bug error message not logged */
        return ERR_SCM_NOMEM;
    /** @bug error code ignored without explanation */
    if (read_objid(&certp->algorithm.algorithm, outer_sig_alg_oidp,
                   length + 1) != length)
    {
        free(outer_sig_alg_oidp);
        LOG(LOG_ERR, "outer sig alg oid actual length != stated length");
        return ERR_SCM_BADALG;
    }

    if (strncmp(outer_sig_alg_oidp, id_sha_256WithRSAEncryption, length) != 0)
    {
        free(outer_sig_alg_oidp);
        LOG(LOG_ERR, "inner sig alg oid does not match spec");
        return ERR_SCM_BADALG;
    }

    length = vsize_objid(&certp->toBeSigned.signature.algorithm);
    if (length <= 0)
    {
        free(outer_sig_alg_oidp);
        LOG(LOG_ERR, "length of inner sig alg oid <= 0");
        return ERR_SCM_BADALG;
    }
    char *inner_sig_alg_oidp = calloc(1, length + 1);
    if (!inner_sig_alg_oidp)
    {
        if (outer_sig_alg_oidp)
            free(outer_sig_alg_oidp);
        return ERR_SCM_NOMEM;
    }
    /** @bug error code ignored without explanation */
    if (read_objid(&certp->toBeSigned.signature.algorithm,
                   inner_sig_alg_oidp, length + 1) != length)
    {
        free(inner_sig_alg_oidp);
        free(outer_sig_alg_oidp);
        LOG(LOG_ERR, "inner sig alg oid actual length != stated length");
        return ERR_SCM_BADALG;
    }

    if (strncmp(inner_sig_alg_oidp, id_sha_256WithRSAEncryption, length) != 0)
    {
        free(inner_sig_alg_oidp);
        free(outer_sig_alg_oidp);
        LOG(LOG_ERR, "inner sig alg oid does not match spec");
        return ERR_SCM_BADALG;
    }

    // amw: Although this is currently redundant, it satisfies a different
    // spec
    // which may change separately.
    if (strncmp(outer_sig_alg_oidp, inner_sig_alg_oidp, length) != 0)
    {
        free(inner_sig_alg_oidp);
        free(outer_sig_alg_oidp);
        LOG(LOG_ERR, "inner and outer sig alg oids do not match");
        return ERR_SCM_BADALG;
    }

    free(inner_sig_alg_oidp);
    free(outer_sig_alg_oidp);

    length =
        vsize_objid(&certp->toBeSigned.subjectPublicKeyInfo.algorithm.
                    algorithm);
    if (length <= 0)
    {
        LOG(LOG_ERR, "length of subj pub key sig alg oid <= 0");
        return ERR_SCM_BADALG;
    }
    char *alg_pubkey_oidp = calloc(1, length + 1);
    if (!alg_pubkey_oidp)
        return ERR_SCM_NOMEM;
    /** @bug error code ignored without explanation */
    if (read_objid(&certp->toBeSigned.subjectPublicKeyInfo.algorithm.algorithm,
                   alg_pubkey_oidp, length + 1) != length)
    {
        free(alg_pubkey_oidp);
        LOG(LOG_ERR,
                "subj pub key sig alg oid actual length != stated length");
        return ERR_SCM_BADALG;
    }

    if (strncmp(alg_pubkey_oidp, id_rsadsi_rsaEncryption, length) != 0)
    {
        free(alg_pubkey_oidp);
        LOG(LOG_ERR, "subj pub key sig alg id does not match spec");
        return ERR_SCM_BADALG;
    }

    free(alg_pubkey_oidp);

    // read the subject public key
    int bytes_to_read =
        vsize_casn(&certp->toBeSigned.subjectPublicKeyInfo.subjectPublicKey);
    if (bytes_to_read > SUBJ_PUBKEY_MAX_SZ)
    {
        LOG(LOG_ERR, "subj pub key too long (%d bytes)", bytes_to_read);
        return ERR_SCM_BADALG;
    }
    uchar *pubkey_buf;
    int bytes_read;
    bytes_read =
        readvsize_casn(&certp->toBeSigned.
                       subjectPublicKeyInfo.subjectPublicKey, &pubkey_buf);
    if (!pubkey_buf)
        return ERR_SCM_NOMEM;
    if (bytes_read != bytes_to_read)
    {
        LOG(LOG_ERR, "subj pub key actual length (%d) != stated (%d)",
            bytes_read, bytes_to_read);
        free(pubkey_buf);
        return ERR_SCM_BADALG;
    }
    if (pubkey_buf[0] != 0)
    {
        LOG(LOG_ERR,
            "subj pub key not a whole number of bytes (between %d and %d)",
            bytes_read - 2, // one for the unused-bits byte
            bytes_read - 1);
        free(pubkey_buf);
        return ERR_SCM_BADALG;
    }

    // interpret the BIT STRING pubkey_buf as a RSAPubKey
    struct RSAPubKey rsapubkey;
    RSAPubKey(&rsapubkey, 0);
    bytes_read = decode_casn(&rsapubkey.self, &pubkey_buf[1]);
    free(pubkey_buf);
    if (bytes_read < 0)
    {
        LOG(LOG_ERR, "error decoding subj pub key");
        delete_casn(&rsapubkey.self);
        return ERR_SCM_BADALG;
    }

    // Subject public key modulus must be (SUBJ_PUBKEY_MODULUS_SZ * 8)-bits.
    uchar *pubkey_modulus_buf;
    bytes_read = readvsize_casn(&rsapubkey.modulus, &pubkey_modulus_buf);
    if (bytes_read < 0)
    {
        LOG(LOG_ERR, "error parsing public key modulus");
        delete_casn(&rsapubkey.self);
        return ERR_SCM_BADALG;
    }
    else if (bytes_read == 0)
    {
        LOG(LOG_ERR, "empty public key modulus");
        free(pubkey_modulus_buf);
        delete_casn(&rsapubkey.self);
        return ERR_SCM_BADALG;
    }
    if (!pubkey_modulus_buf)
    {
        delete_casn(&rsapubkey.self);
        return ERR_SCM_NOMEM;
    }
    if (pubkey_modulus_buf[0] & 0x80)
    {
        LOG(LOG_ERR, "subj pub key modulus is negative (length = %d bytes)",
            bytes_read);
        free(pubkey_modulus_buf);
        delete_casn(&rsapubkey.self);
        return ERR_SCM_BADALG;
    }
    int modulus_bit_length;
    if (pubkey_modulus_buf[0] == 0)
    {
        if (bytes_read > 1 && (pubkey_modulus_buf[1] & 0x80) == 0)
        {
            LOG(LOG_ERR, "subj pub key modulus has leading zero-byte "
                "(length = %d bytes)", bytes_read);
            free(pubkey_modulus_buf);
            delete_casn(&rsapubkey.self);
            return ERR_SCM_BADALG;
        }

        modulus_bit_length = (bytes_read - 1) * 8;
    }
    else
    {
        modulus_bit_length = bytes_read * 8;
        uint8_t bit_mask;
        for (bit_mask = 0x80;
            bit_mask > 0 && (pubkey_modulus_buf[0] & bit_mask) == 0;
            bit_mask >>= 1)
        {
            --modulus_bit_length;
        }
    }
    if (modulus_bit_length != SUBJ_PUBKEY_MODULUS_SZ * 8)
    {
        if (modulus_bit_length == 1024 && !strict_profile_checks)
        {
            LOG(LOG_WARNING, "subj pub key modulus bit-length (%d) != %d",
                modulus_bit_length, SUBJ_PUBKEY_MODULUS_SZ * 8);
        }
        else
        {
            LOG(LOG_ERR, "subj pub key modulus bit-length (%d) != %d",
                modulus_bit_length, SUBJ_PUBKEY_MODULUS_SZ * 8);
            free(pubkey_modulus_buf);
            delete_casn(&rsapubkey.self);
            return ERR_SCM_BADALG;
        }
    }
    free(pubkey_modulus_buf);

    // Subject public key exponent must = 65,537.
    long exponent;
    if (read_casn_num(&rsapubkey.exponent, &exponent) < 0)
    {
        LOG(LOG_ERR, "error reading subj pub key exponent");
        delete_casn(&rsapubkey.self);
        return ERR_SCM_BADALG;
    }
    if (exponent != SUBJ_PUBKEY_EXPONENT)
    {
        LOG(LOG_ERR, "subj pub key exponent != %d", SUBJ_PUBKEY_EXPONENT);
        delete_casn(&rsapubkey.self);
        return ERR_SCM_BADALG;
    }

    delete_casn(&rsapubkey.self);

    return 0;
}


/**=============================================================================
 * @brief Check that the cert's serial number meets spec.
 *
 * @param certp (struct Certificate*)
 * @retval ret 0 on success<br />a negative integer on failure
 -----------------------------------------------------------------------------*/
static err_code
rescert_serial_number_chk(
    struct Certificate *certp)
{
    int i;

    int bytes_to_read = vsize_casn(&certp->toBeSigned.serialNumber);
    if (bytes_to_read > SER_NUM_MAX_SZ)
    {
        LOG(LOG_ERR, "serial number field too long");
        return (ERR_SCM_BADSERNUM);
    }

    uint8_t *sernump;
    int bytes_read = readvsize_casn(&certp->toBeSigned.serialNumber, &sernump);
    if (!sernump)
        return ERR_SCM_NOMEM;
    if (bytes_read != bytes_to_read)
    {
        LOG(LOG_ERR, "serial number actual length != stated length");
        free(sernump);
        return (ERR_SCM_BADSERNUM);
    }

    if (*sernump & 0x80)
    {
        LOG(LOG_ERR, "serial number is negative");
        free(sernump);
        return (ERR_SCM_BADSERNUM);
    }

    bool is_zero = true;
    for (i = 0; i < bytes_read; ++i)
    {
        if (sernump[i] != 0)
        {
            is_zero = false;
            break;
        }
    }
    if (is_zero)
    {
        LOG(LOG_ERR, "serial number is zero");
        free(sernump);
        return ERR_SCM_BADSERNUM;
    }

    free(sernump);

    return 0;
}


/**=============================================================================
 * @brief Date-related checks
 *
 * @param certp (struct Certificate*)
 * @retval ret 0 on success<br />a negative integer on failure
 -----------------------------------------------------------------------------*/
static err_code
rescert_dates_chk(
    struct Certificate *certp)
{
    if (diff_casn_time(&certp->toBeSigned.validity.notBefore.self,
                       &certp->toBeSigned.validity.notAfter.self) > 0)
    {
        LOG(LOG_ERR, "invalid certificate, notBefore > notAfter");
        return ERR_SCM_BADDATES;        // I am the monarch of the sea.  I am
                                        // the ruler of the qu...
    }

    return 0;
}


/**=============================================================================
 * @brief Check for issuer UID or subject UID
 *
 * @param certp (struct Certificate*)
 * @return 0 on success<br />a negative integer on failure
 -----------------------------------------------------------------------------*/
static err_code
rescert_subj_iss_UID_chk(
    struct Certificate *certp)
{
    if (size_casn(&certp->toBeSigned.issuerUniqueID) > 0)
    {
        LOG(LOG_ERR, "certificate has issuer unique ID");
        return ERR_SCM_XPROFILE;
    }

    if (size_casn(&certp->toBeSigned.subjectUniqueID) > 0)
    {
        LOG(LOG_ERR, "certificate has subject unique ID");
        return ERR_SCM_XPROFILE;
    }

    return 0;
}


/**
    @brief Check for unknown extensions.
*/
static err_code
rescert_extensions_chk(
    struct Certificate *certp)
{
    static char const *const allowed_extensions[] = {
        id_basicConstraints,
        id_subjectKeyIdentifier,
        id_authKeyId,
        id_keyUsage,
        id_extKeyUsage,         // allowed in future BGPSEC EE certs
        id_cRLDistributionPoints,
        id_pkix_authorityInfoAccess,
        id_pe_subjectInfoAccess,
        id_certificatePolicies,
        id_pe_ipAddrBlock,
        id_pe_autonomousSysNum,
        NULL
    };

    // to prevent memory overflows
    static const int max_oid_print_length = 50;

    struct Extension *extp = NULL;
    bool ext_allowed;
    size_t i;

    for (extp =
         (struct Extension *)member_casn(&certp->toBeSigned.extensions.self,
                                         0); extp != NULL;
         extp = (struct Extension *)next_of(&extp->self))
    {
        ext_allowed = false;
        for (i = 0; allowed_extensions[i] != NULL; ++i)
        {
            /** @bug error code ignored without explanation */
            if (!diff_objid(&extp->extnID, allowed_extensions[i]))
            {
                ext_allowed = true;
                break;
            }
        }

        if (!ext_allowed)
        {
            int oid_size = vsize_objid(&extp->extnID);
            char oid_print[max_oid_print_length + 1];

            if (oid_size > max_oid_print_length)
            {
                xsnprintf(oid_print, sizeof(oid_print),
                          "<oid too large to print>");
            }
            else
            {
                /** @bug error code ignored without explanation */
                read_objid(&extp->extnID, oid_print, sizeof(oid_print));
            }
            LOG(LOG_ERR, "certificate has unknown extension %s",
                    oid_print);
            return ERR_SCM_BADEXT;
        }
    }

    return 0;
}


err_code
rescert_profile_chk(
    X509 *x,
    struct Certificate *certp,
    int ct)
{
    LOG(LOG_DEBUG, "rescert_profile_chk(x=%p, certp=%p, ct=%d)", x, certp, ct);

    err_code ret = 0;

    if (x == NULL || ct == UN_CERT)
    {
        LOG(LOG_ERR, "invalid argument passed to rescert_profile_chk()");
        ret = ERR_SCM_INVALARG;
        goto done;
    }
    /*
     * load the X509_st extension values
     */
    x509v3_load_extensions(x);

    if ((x->ex_flags & EXFLAG_INVALID) != 0 || (x->ex_flags & EXFLAG_SET) == 0)
    {
        LOG(LOG_ERR, "invalid certificate extension");
        ret = ERR_SCM_BADEXT;
        goto done;
    }

    ret = rescert_flags_chk(x, ct);
    if (ret < 0)
    {
        goto done;
    }

    ret = rescert_version_chk(x);
    if (ret < 0)
    {
        goto done;
    }

    if (rescert_name_chk(&certp->toBeSigned.issuer.rDNSequence) < 0)
    {
        ret = ERR_SCM_BADISSUER;
        goto done;
    }
    else if (rescert_name_chk(&certp->toBeSigned.subject.rDNSequence) < 0)
    {
        ret = ERR_SCM_BADSUBJECT;
        goto done;
    }

    ret = rescert_basic_constraints_chk(x, ct);
    LOG(LOG_DEBUG, "rescert_basic_constraints_chk");
    if (ret < 0)
    {
        goto done;
    }

    ret = rescert_ski_chk(x, certp);
    LOG(LOG_DEBUG, "rescert_ski_chk");
    if (ret < 0)
    {
        goto done;
    }

    ret = rescert_aki_chk(x, ct);
    LOG(LOG_DEBUG, "rescert_aki_chk");
    if (ret < 0)
    {
        goto done;
    }

    ret = rescert_key_usage_chk(x);
    LOG(LOG_DEBUG, "rescert_key_usage_chk");
    if (ret < 0)
    {
        goto done;
    }

    ret = rescert_extended_key_usage_chk(x, ct);
    LOG(LOG_DEBUG, "rescert_extended_key_usage_chk");
    if (ret < 0)
    {
        goto done;
    }

    ret = rescert_crldp_chk(x, ct);
    LOG(LOG_DEBUG, "rescert_crldp_chk");
    if (ret < 0)
    {
        goto done;
    }

    ret = rescert_aia_chk(x, ct);
    LOG(LOG_DEBUG, "rescert_aia_chk");
    if (ret < 0)
    {
        goto done;
    }

    ret = rescert_sia_chk(certp);
    LOG(LOG_DEBUG, "rescert_sia_chk");
    if (ret < 0)
    {
        goto done;
    }

    ret = rescert_cert_policy_chk(x);
    LOG(LOG_DEBUG, "rescert_cert_policy_chk");
    if (ret < 0)
    {
        goto done;
    }

    ret = rescert_ip_asnum_chk(x, certp, ct);
    LOG(LOG_DEBUG, "rescert_ip_asnum_chk");
    if (ret < 0)
    {
        goto done;
    }

    ret = rescert_criticals_chk(x);
    LOG(LOG_DEBUG, "rescert_criticals_chk");
    if (ret < 0)
    {
        goto done;
    }

    ret = rescert_sig_algs_chk(certp);
    LOG(LOG_DEBUG, "rescert_sig_algs_chk");
    if (ret < 0)
    {
        goto done;
    }

    ret = rescert_serial_number_chk(certp);
    LOG(LOG_DEBUG, "rescert_serial_number_chk");
    if (ret < 0)
    {
        goto done;
    }

    ret = rescert_dates_chk(certp);
    LOG(LOG_DEBUG, "rescert_dates_chk");
    if (ret < 0)
    {
        goto done;
    }

    ret = rescert_subj_iss_UID_chk(certp);
    LOG(LOG_DEBUG, "rescert_subj_iss_UID_chk");
    if (ret < 0)
    {
        goto done;
    }

    ret = rescert_extensions_chk(certp);
    LOG(LOG_DEBUG, "rescert_extensions_chk");
    if (ret < 0)
    {
        goto done;
    }

done:
    LOG(LOG_DEBUG, "rescert_profile_chk() returning %s: %s",
        err2name(ret), err2string(ret));
    return ret;
}


/**=============================================================================
 * @brief Check CRL version number
 *
 * @param crlp (struct CertificateRevocationList*)
 * @return 0 on success<br />a negative integer on failure
 *
 * RFC 5280:
 * TBSCertList  ::=  SEQUENCE  {
 *      version                 Version OPTIONAL,
 *                                   -- if present, MUST be v2
 *      ...
 *
 * draft-ietf-sidr-res-certs:
 * Each CA MUST issue a version 2 Certificate Revocation List (CRL),
 * consistent with [RFC5280].  RPs are NOT required to process version 1
 * CRLs (in contrast to [RFC5280]).
 -----------------------------------------------------------------------------*/
static err_code
crl_version_chk(
    struct CertificateRevocationList *crlp)
{
    int ret = 0;
    long version = 0;

    if (!crlp)
        return ERR_SCM_INTERNAL;

    ret = read_casn_num(&crlp->toBeSigned.version.self, &version);
    if (ret < 0)
        return ERR_SCM_NOCRLVER;

    if (version != 1)           // CRL v2 = integer value 1
        return ERR_SCM_BADCRLVER;

    return 0;
}


/**=============================================================================
 * @brief Check CRL inner and outer signature algorithms
 *
 * @param crlp (struct CertificateRevocationList*)
 * @return 0 on success<br />a negative integer on failure
 *
 * When used to generate and verify digital signatures the hash and
 * digital signature algorithms are referred together, i.e., "RSA PKCS#1
 * v1.5 with SHA-256" or more simply "RSA with SHA-256".  The Object
 * Identifier (OID) sha256withRSAEncryption from [RFC4055] MUST be used.
 -----------------------------------------------------------------------------*/
static err_code
crl_sigalg_chk(
    struct CertificateRevocationList *crlp)
{
    if (!crlp)
        return ERR_SCM_INTERNAL;
    /** @bug error code ignored without explanation */
    if (diff_objid(&crlp->toBeSigned.signature.algorithm,
                   id_sha_256WithRSAEncryption) != 0)
    {
        LOG(LOG_ERR, "Wrong CRL inner signature algorithm");
        return ERR_SCM_BADSIGALG;
    }
    /** @bug error code ignored without explanation */
    if (diff_objid(&crlp->algorithm.algorithm,
                   id_sha_256WithRSAEncryption) != 0)
    {
        LOG(LOG_ERR, "Wrong CRL outer signature algorithm");
        return ERR_SCM_BADSIGALG;
    }
    return 0;
}


/**=============================================================================
 * @brief Check CRL issuer against draft-ietf-sidr-res-certs
 *
 * @param crlp (struct CertificateRevocationList*)
 * @return 0 on success<br />a negative integer on failure
 *
 * http://tools.ietf.org/html/draft-ietf-sidr-res-certs-22#section-4.4
 * (same as for certificates)
 -----------------------------------------------------------------------------*/
static err_code
crl_issuer_chk(
    struct CertificateRevocationList *crlp)
{
    if (!crlp)
        return ERR_SCM_INTERNAL;
    if (rescert_name_chk(&crlp->toBeSigned.issuer.rDNSequence) < 0)
    {
        LOG(LOG_ERR, "Bad CRL issuer");
        return ERR_SCM_BADISSUER;
    }
    return 0;
}

/**
 * @brief
 *     Check whether the ::ChoiceOfTime is convertible to a
 *     database-style date and time.
 */
static err_code
cvt_crldate2DB(
    struct ChoiceOfTime *cotp)
{
    char *buf = NULL;
    int i = vsize_casn(&cotp->utcTime);
    if (i > 0)                  // utc time
    {
        if (i != 13)
            return ERR_SCM_INVALDT;
        if (!(buf = (char *)calloc(1, i + 2)))
            return ERR_SCM_NOMEM;
        read_casn(&cotp->utcTime, (uchar *) buf);
    }
    else                        // generalTime
    {
        i = vsize_casn(&cotp->generalTime);
        if (i < 15)
            return ERR_SCM_INVALDT;
        if (!(buf = (char *)calloc(1, i + 2)))
            return ERR_SCM_NOMEM;
        read_casn(&cotp->generalTime, (uchar *) buf);
        if (i > 15 && (buf[i - 1] == '0' || buf[i - 1] == '.'))
        {
            free(buf);
            return ERR_SCM_INVALDT;
        }
    }
    err_code sta = 0;
    free(ASNTimeToDBTime(buf, &sta, 0));
    free(buf);
    return sta;
}

static err_code
crl_dates_chk(
    struct CertificateRevocationList *crlp)
{
    if (!crlp)
        return ERR_SCM_INTERNAL;
    struct CertificateRevocationListToBeSigned *crltbsp = &crlp->toBeSigned;

    int ret = diff_casn_time(&crltbsp->lastUpdate.self,
                             &crltbsp->nextUpdate.self);
    if (ret == -2)
    {
        LOG(LOG_ERR, "failed to read CRL time field(s)");
        return ERR_SCM_INVALDT;
    }
    if (cvt_crldate2DB(&crltbsp->lastUpdate) < 0 ||
        cvt_crldate2DB(&crltbsp->nextUpdate) < 0)
    {
        LOG(LOG_ERR, "CRL time field(s) don't fit into database");
        return ERR_SCM_INTERNAL;
    }
    if (ret > 0)
    {
        LOG(LOG_ERR, "Invalid CRL, thisUpdate > nextUpdate");
        return ERR_SCM_BADDATES;
    }
    time_t now;
    int64_t lastdate;
    time(&now);
    read_casn_time(&crltbsp->lastUpdate.self, &lastdate);
    if (lastdate > now)
    {
        int64_t secsInFuture = lastdate - now;
        // TODO: if (secsInFuture > user_configured_limit) { log; return
        // ERR_SCM_INVALDT; }
        LOG(LOG_WARNING, "thisUpdate %" PRId64 " seconds in the future",
                secsInFuture);
    }
    return 0;
}


/**=============================================================================
 * @brief Check one CRL entry against draft-ietf-sidr-res-certs, section 5
 *
 * @param entryp (struct CRLEntry*)
 * @retval ret 0 on success<br />a negative integer on failure
 *
 * For each revoked resource certificate only the two fields Serial
 * Number and Revocation Date MUST be present, and all other fields
 * MUST NOT be present.  No CRL entry extensions are supported in this
 * profile, and CRL entry extensions MUST NOT be present in a CRL.
 -----------------------------------------------------------------------------*/
static err_code
crl_entry_chk(
    struct CRLEntry *entryp)
{
    if (!entryp)
        return ERR_SCM_INTERNAL;

    uint8_t snum[CRL_MAX_SNUM_LTH];
    int snum_length;
    int i;

    // Forbid CRLEntryExtensions
    if (size_casn(&entryp->extensions.self) > 0)
    {
        LOG(LOG_ERR, "Revocation entry has extension(s)");
        return ERR_SCM_CRLENTRYEXT;
    }

    // check serial number
    if (vsize_casn(&entryp->userCertificate) > CRL_MAX_SNUM_LTH)
    {
        LOG(LOG_WARNING, "Revoked serial number too long");
    }
    else
    {
        snum_length = read_casn(&entryp->userCertificate, snum);
        if (snum_length <= 0)
        {
            LOG(LOG_ERR, "Invalid revoked serial number");
            return ERR_SCM_BADREVSNUM;
        }

        if (snum[0] & 0x80)
        {
            LOG(LOG_WARNING, "Negative revoked serial number");
        }
        else
        {
            bool snum_is_zero = true;
            for (i = 0; i < snum_length; ++i)
            {
                if (snum[i] != 0)
                {
                    snum_is_zero = false;
                    break;
                }
            }
            if (snum_is_zero)
            {
                LOG(LOG_WARNING, "Revoked serial number is zero");
            }
        }
    }

    // and the date
    int64_t revdate = 0;
    int64_t now = time(0);
    if (read_casn_time(&entryp->revocationDate.self, &revdate) < 0)
    {
        LOG(LOG_ERR, "Invalid revocation date");
        return ERR_SCM_BADREVDATE;
    }
    if (revdate > now)
    {
        LOG(LOG_WARNING, "Revocation date in the future");
    }
    if (cvt_crldate2DB(&entryp->revocationDate) < 0)
    {
        LOG(LOG_ERR, "Revocation date doesn't fit in database");
        return ERR_SCM_INTERNAL;
    }

    return 0;
}


/**=============================================================================
 * @brief Check CRL entries against draft-ietf-sidr-res-certs, section 5
 *
 * @param crlp (struct CertificateRevocationList *)
 * @retval ret 0 on success<br />a negative integer on failure
 *
 * No CRL entry extensions are supported in this
 * profile, and CRL entry extensions MUST NOT be present in a CRL.
 -----------------------------------------------------------------------------*/
static err_code
crl_entries_chk(
    struct CertificateRevocationList *crlp)
{
    struct RevokedCertificatesInCertificateRevocationListToBeSigned *revlistp =
        0;
    struct CRLEntry *entryp = 0;

    if (!crlp)
        return ERR_SCM_INTERNAL;
    revlistp = &crlp->toBeSigned.revokedCertificates;
    for (entryp = (struct CRLEntry *)member_casn(&revlistp->self, 0);
         entryp != NULL; entryp = (struct CRLEntry *)next_of(&entryp->self))
    {
        err_code ret = crl_entry_chk(entryp);
        if (ret < 0)
            return ret;
    }
    return 0;
}


/**=============================================================================
 * @brief Check CRL AKI against draft-ietf-sidr-res-certs, section 5
 *
 * @param crlp (struct CertificateRevocationList *)
 * @retval ret 0 on success<br />a negative integer on failure
 *
 * An RPKI CA MUST include the two extensions Authority Key Identifier
 * and CRL Number in every CRL that it issues.  RPs MUST be prepared
 * to process CRLs with these extensions.  No other CRL extensions are
 * allowed.
 -----------------------------------------------------------------------------*/
static err_code
crl_extensions_chk(
    struct CertificateRevocationList *crlp)
{
    // Check for exactly one AKI extension and one CRL number extension
    struct CrlExtensions *crlextsp = &crlp->toBeSigned.extensions;
    struct AuthorityKeyId *authkeyIdp = NULL;
    struct CRLNumber *crlnump = NULL;
    struct CRLExtension *crlextp;
    long i;
    for (crlextp = (struct CRLExtension *)member_casn(&crlextsp->self, 0);
         crlextp; crlextp = (struct CRLExtension *)next_of(&crlextp->self))
    {
        /** @bug error code ignored without explanation */
        if (!diff_objid(&crlextp->extnID, id_authKeyId))
        {
            i = 0;
            if (read_casn_num(&crlextp->critical, &i) >= 0 && i > 0)
            {
                LOG(LOG_ERR,
                        "CRL Authority Key Identifier extension marked critical");
                return ERR_SCM_CEXT;
            }
            if (authkeyIdp)
            {
                LOG(LOG_ERR,
                        "Duplicate CRL Authority Key Identifier extension");
                return ERR_SCM_BADEXT;
            }
            authkeyIdp = &crlextp->extnValue.authKeyId;
        }
        /** @bug error code ignored without explanation */
        else if (!diff_objid(&crlextp->extnID, id_cRLNumber))
        {
            i = 0;
            if (read_casn_num(&crlextp->critical, &i) >= 0 && i > 0)
            {
                LOG(LOG_ERR, "CRL number extension marked critical");
                return ERR_SCM_CEXT;
            }
            if (crlnump)
            {
                LOG(LOG_ERR, "Duplicate CRL number extension");
                return ERR_SCM_BADEXT;
            }
            crlnump = &crlextp->extnValue.cRLNumber;
        }
        else
        {
            // Forbid any other extension
            LOG(LOG_ERR, "Forbidden CRL extension");
            char *oidp;
            i = vsize_objid(&crlextp->extnID);
            if (i > 0)
            {
                if (!(oidp = (char *)calloc(1, i + 2)))
                {
                    LOG(LOG_ERR, "Can't get memory while checking CRL");
                    return ERR_SCM_NOMEM;
                }
            }
            else
            {
                return ERR_SCM_BADEXT;
            }
            if (read_objid(&crlextp->extnID, oidp, i + 2) <= 0)
            {
                free(oidp);
                LOG(LOG_ERR, "Error reading CRLExtension OID");
                return ERR_SCM_BADEXT;
            }
            LOG(LOG_ERR, "Forbidden extension oid %s", oidp);
            free(oidp);
            return ERR_SCM_BADEXT;
        }
    }
    if (!authkeyIdp)
    {
        LOG(LOG_ERR, "No Authority Key Identifier extension");
        return ERR_SCM_NOAKI;
    }
    if (!crlnump)
    {
        LOG(LOG_ERR, "No CRL number extension");
        return ERR_SCM_NOCRLNUM;
    }
    else
    {
        uint8_t num[CRL_MAX_CRLNUM_LTH];

        if (vsize_casn(crlnump) <= 0)
        {
            LOG(LOG_ERR, "error reading CRLNumber");
            return ERR_SCM_BADCRLNUM;
        }
        else if (vsize_casn(crlnump) > CRL_MAX_CRLNUM_LTH)
        {
            LOG(LOG_ERR, "CRLNumber too long");
            return ERR_SCM_BADCRLNUM;
        }

        read_casn(crlnump, num);

        if (num[0] & 0x80)
        {
            LOG(LOG_ERR, "CRLNumber is negative");
            return ERR_SCM_BADCRLNUM;
        }
    }
    return 0;
}

err_code
crl_profile_chk(
    struct CertificateRevocationList *crlp)
{
    err_code ret = 0;

    if (!crlp)
        return ERR_SCM_INTERNAL;

    LOG(LOG_DEBUG, "crl_version_chk");
    ret = crl_version_chk(crlp);
    if (ret < 0)
        return ret;

    LOG(LOG_DEBUG, "crl_sigalg_chk");
    ret = crl_sigalg_chk(crlp);
    if (ret < 0)
        return ret;

    LOG(LOG_DEBUG, "crl_issuer_chk");
    ret = crl_issuer_chk(crlp);
    if (ret < 0)
        return ret;

    LOG(LOG_DEBUG, "crl_dates_chk");
    ret = crl_dates_chk(crlp);
    if (ret < 0)
        return ret;

    LOG(LOG_DEBUG, "crl_entries_chk");
    ret = crl_entries_chk(crlp);
    if (ret < 0)
        return ret;

    LOG(LOG_DEBUG, "crl_extensions_chk");
    ret = crl_extensions_chk(crlp);
    if (ret < 0)
        return ret;

    return 0;
}
