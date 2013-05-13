/*
 * $Id$ 
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <ctype.h>
#include <syslog.h>
#include <assert.h>
#include <mysql.h>

#include "globals.h"
#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "diru.h"
#include "myssl.h"
#include "err.h"
#include "rpwork.h"
#include "casn/casn.h"
#include "rpki-asn1/crlv2.h"

#include "cms/roa_utils.h"
#include "util/logging.h"


#define ADDCOL(a, b, c, d, e, f)  \
       e = addcolsrchscm (a, b, c, d);  \
       if ( e < 0 ) return f;

/*
 * static variables that hold tables and function to initialize them
 */

static scmtab *theCertTable = NULL;
static scmtab *theROATable = NULL;
static scmtab *theCRLTable = NULL;
static scmtab *theManifestTable = NULL;
static scmtab *theDirTable = NULL;
static scmtab *theMetaTable = NULL;
static scm *theSCMP = NULL;
static int useParacerts = 1;
static int allowex = 0;

void setallowexpired(
    int v)
{
    allowex = (v == 0 ? 0 : 1);
}

static void initTables(
    scm * scmp)
{
    if (theCertTable == NULL)
    {
        theDirTable = findtablescm(scmp, "DIRECTORY");
        if (theDirTable == NULL)
        {
            LOG(LOG_ERR, "Error finding directory table");
            exit(-1);
        }
        theMetaTable = findtablescm(scmp, "METADATA");
        if (theMetaTable == NULL)
        {
            LOG(LOG_ERR, "Error finding metadata table");
            exit(-1);
        }
        theCertTable = findtablescm(scmp, "CERTIFICATE");
        if (theCertTable == NULL)
        {
            LOG(LOG_ERR, "Error finding certificate table");
            exit(-1);
        }
        theCRLTable = findtablescm(scmp, "CRL");
        if (theCRLTable == NULL)
        {
            LOG(LOG_ERR, "Error finding crl table");
            exit(-1);
        }
        theROATable = findtablescm(scmp, "ROA");
        if (theROATable == NULL)
        {
            LOG(LOG_ERR, "Error finding roa table");
            exit(-1);
        }
        theManifestTable = findtablescm(scmp, "MANIFEST");
        if (theManifestTable == NULL)
        {
            LOG(LOG_ERR, "Error finding manifest table");
            exit(-1);
        }
        theSCMP = scmp;
    }
}

/*
 * Find a directory in the directory table, or create it if it is not found.
 * Return the id in idp. The function returns 0 on success and a negative
 * error code on failure.
 * 
 * It is assumed that the existence of the putative directory has already been
 * verified. 
 */

int findorcreatedir(
    scm * scmp,
    scmcon * conp,
    char *dirname,
    unsigned int *idp)
{
    scmsrcha *srch;
    scmkva where;
    scmkva ins;
    scmkv two[2];
    int sta;

    if (conp == NULL || conp->connected == 0 || dirname == NULL ||
        dirname[0] == 0 || idp == NULL)
        return (ERR_SCM_INVALARG);
    *idp = (unsigned int)(-1);
    conp->mystat.tabname = "DIRECTORY";
    initTables(scmp);
    two[0].column = "dir_id";
    two[0].value = NULL;
    two[1].column = "dirname";
    two[1].value = dirname;
    where.vec = &two[1];
    where.ntot = 1;
    where.nused = 1;
    where.vald = 0;
    ins.vec = &two[0];
    ins.ntot = 2;
    ins.nused = 2;
    ins.vald = 0;
    srch = newsrchscm("focdir", 4, sizeof(unsigned int), 0);
    if (srch == NULL)
        return (ERR_SCM_NOMEM);
    sta = addcolsrchscm(srch, "dir_id", SQL_C_ULONG, sizeof(unsigned int));
    if (sta < 0)
    {
        freesrchscm(srch);
        return (sta);
    }
    srch->where = &where;
    sta = searchorcreatescm(scmp, conp, theDirTable, srch, &ins, idp);
    freesrchscm(srch);
    return (sta);
}

static int ok(
    scmcon * conp,
    scmsrcha * s,
    int idx)
{
    UNREFERENCED_PARAMETER(conp);
    UNREFERENCED_PARAMETER(s);
    UNREFERENCED_PARAMETER(idx);
    return (0);
}

/*
 * Ask the DB about the top level repos directory. If found return a copy of
 * the dirname. On error return NULL and set stap. 
 */

char *retrieve_tdir(
    scm * scmp,
    scmcon * conp,
    int *stap)
{
    unsigned int blah;
    scmsrcha srch;
    scmsrch srch1;
    scmkva where;
    scmkv one;
    char *oot;
    int sta;

    if (scmp == NULL || conp == NULL || conp->connected == 0 || stap == NULL)
        return (NULL);
    conp->mystat.tabname = "METADATA";
    initTables(scmp);
    one.column = "local_id";
    one.value = "1";
    where.vec = &one;
    where.ntot = 1;
    where.nused = 1;
    where.vald = 0;
    srch1.colno = 1;
    srch1.sqltype = SQL_C_CHAR;
    srch1.colname = "rootdir";
    oot = (char *)calloc(PATH_MAX, sizeof(char));
    if (oot == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        return (NULL);
    }
    srch1.valptr = (void *)oot;
    srch1.valsize = PATH_MAX;
    srch1.avalsize = 0;
    srch.vec = &srch1;
    srch.sname = NULL;
    srch.ntot = 1;
    srch.nused = 1;
    srch.vald = 0;
    srch.where = &where;
    srch.wherestr = NULL;
    srch.context = &blah;
    sta = searchscm(conp, theMetaTable, &srch, NULL,
                    ok, SCM_SRCH_DOVALUE_ALWAYS, NULL);
    if (sta < 0)
    {
        free((void *)oot);
        oot = NULL;
    }
    *stap = sta;
    return (oot);
}

/*
 * Ask the DB if it has any matching signatures to the one passed in. This
 * function works on any of the three tables that have signatures. 
 */

static int dupsigscm(
    scm * scmp,
    scmcon * conp,
    scmtab * tabp,
    char *msig)
{
    unsigned int blah;
    unsigned long lid;
    scmsrcha srch;
    scmsrch srch1;
    scmkva where;
    scmkv one;
    int sta;

    if (scmp == NULL || conp == NULL || conp->connected == 0 ||
        tabp == NULL || msig == NULL || msig[0] == 0)
        return (ERR_SCM_INVALARG);
    conp->mystat.tabname = tabp->hname;
    initTables(scmp);
    one.column = "sig";
    one.value = msig;
    where.vec = &one;
    where.ntot = 1;
    where.nused = 1;
    where.vald = 0;
    srch1.colno = 1;
    srch1.sqltype = SQL_C_LONG;
    srch1.colname = "local_id";
    srch1.valptr = (void *)&lid;
    srch1.valsize = sizeof(unsigned long);
    srch1.avalsize = 0;
    srch.vec = &srch1;
    srch.sname = NULL;
    srch.ntot = 1;
    srch.nused = 1;
    srch.vald = 0;
    srch.where = &where;
    srch.wherestr = NULL;
    srch.context = &blah;
    sta = searchscm(conp, tabp, &srch, NULL,
                    ok, SCM_SRCH_DOVALUE_ALWAYS, NULL);
    switch (sta)
    {
    case 0:                    /* found a duplicate sig */
        return (ERR_SCM_DUPSIG);
    case ERR_SCM_NODATA:       /* no duplicate sig */
        return (0);
    default:                   /* some other error */
        return (sta);
    }
}

/*
 * Infer the object type based on which file extensions are present. The
 * following can be present: .cer, .crl and .roa; .pem can also be present. If 
 * there is no suffix, then also check to see if the filename is of the form
 * HHHHHHHH.N, where "HHHHHHHH" is eight hex digits, and .N is an integer
 * suffix. In this case, it is a cert. If nothing can be determined then
 * return unknown.
 * 
 * On success this function returns one of the types defined in sqhl.h; on
 * failure it returns a negative error code. 
 */

int infer_filetype(
    char *fname)
{
    int pem = 0;
    int typ = 0;

    if (fname == NULL || fname[0] == 0)
        return (ERR_SCM_INVALARG);

    if (strstr(fname, ".pem") != NULL)
        pem = 1;
    if (strstr(fname, ".cer") != NULL)
        typ += OT_CER;
    if (strstr(fname, ".crl") != NULL)
        typ += OT_CRL;
    if (strstr(fname, ".roa") != NULL && !typ)
        typ += OT_ROA;
    if ((strstr(fname, ".man") != NULL || strstr(fname, ".mft") != NULL ||
         strstr(fname, ".mnf") != NULL) && !typ)
        typ += OT_MAN;
    if (typ < OT_UNKNOWN || typ > OT_MAXBASIC)
        return (ERR_SCM_INVALFN);
    if (pem > 0)
        typ += OT_PEM_OFFSET;
    return (typ);
}

// so that manifest can get id of previous cert

static unsigned int lastCertIDAdded = 0;

static char *certf[CF_NFIELDS] = {
    "filename", "subject", "issuer", "sn", "valfrom", "valto", "sig",
    "ski", "aki", "sia", "aia", "crldp"
};

static int add_cert_internal(
    scm * scmp,
    scmcon * conp,
    cert_fields * cf,
    unsigned int *cert_id)
{
    scmkva aone;
    scmkv cols[CF_NFIELDS + 5];
    char *wptr = NULL;
    char *ptr;
    char flagn[24];
    char lid[24];
    char did[24];
    char blen[24];
    int idx = 0;
    int sta;
    int i;

    initTables(scmp);
    sta = getmaxidscm(scmp, conp, "local_id", theCertTable, cert_id);
    if (sta < 0)
        return (sta);
    (*cert_id)++;
    // immediately check for duplicate signature
    sta = dupsigscm(scmp, conp, theCertTable, cf->fields[CF_FIELD_SIGNATURE]);
    if (sta < 0)
        return (sta);
    // fill in insertion structure
    for (i = 0; i < CF_NFIELDS + 5; i++)
        cols[i].value = NULL;
    for (i = 0; i < CF_NFIELDS; i++)
    {
        if ((ptr = cf->fields[i]) != NULL)
        {
            cols[idx].column = certf[i];
            cols[idx++].value = ptr;
        }
    }
    (void)snprintf(flagn, sizeof(flagn), "%u", cf->flags);
    cols[idx].column = "flags";
    cols[idx++].value = flagn;
    (void)snprintf(lid, sizeof(lid), "%u", *cert_id);
    cols[idx].column = "local_id";
    cols[idx++].value = lid;
    (void)snprintf(did, sizeof(did), "%u", cf->dirid);
    cols[idx].column = "dir_id";
    cols[idx++].value = did;
    if (cf->ipblen > 0)
    {
        cols[idx].column = "ipblen";
        (void)snprintf(blen, sizeof(blen), "%u", cf->ipblen);   /* byte length 
                                                                 */
        cols[idx++].value = blen;
        cols[idx].column = "ipb";
        wptr = hexify(cf->ipblen, cf->ipb, HEXIFY_HAT);
        if (wptr == NULL)
            return (ERR_SCM_NOMEM);
        cols[idx++].value = wptr;
    }
    aone.vec = &cols[0];
    aone.ntot = CF_NFIELDS + 5;
    aone.nused = idx;
    aone.vald = 0;
    sta = insertscm(conp, theCertTable, &aone);
    if (wptr != NULL)
        free((void *)wptr);
    lastCertIDAdded = *cert_id;
    return (sta);
}

static char *crlf[CRF_NFIELDS] = {
    "filename", "issuer", "last_upd", "next_upd", "sig", "crlno", "aki"
};

static int add_crl_internal(
    scm * scmp,
    scmcon * conp,
    crl_fields * cf)
{
    unsigned int crl_id = 0;
    scmkva aone;
    scmkv cols[CRF_NFIELDS + 6];
    char *ptr;
    char *hexs;
    char flagn[24];
    char lid[24];
    char did[24];
    char csnlen[24];
    int idx = 0;
    int sta;
    int i;

    // immediately check for duplicate signature
    initTables(scmp);
    sta = dupsigscm(scmp, conp, theCRLTable, cf->fields[CRF_FIELD_SIGNATURE]);
    if (sta < 0)
        return (sta);
    // the following statement could use a LOT of memory, so we try
    // it early in case it fails
    hexs = hexify(cf->snlen * SER_NUM_MAX_SZ, cf->snlist, HEXIFY_HAT);
    if (hexs == NULL)
        return (ERR_SCM_NOMEM);
    conp->mystat.tabname = "CRL";
    sta = getmaxidscm(scmp, conp, "local_id", theCRLTable, &crl_id);
    if (sta < 0)
    {
        free((void *)hexs);
        return (sta);
    }
    crl_id++;
    // fill in insertion structure
    for (i = 0; i < CRF_NFIELDS + 6; i++)
        cols[i].value = NULL;
    for (i = 0; i < CRF_NFIELDS; i++)
    {
        if ((ptr = cf->fields[i]) != NULL)
        {
            cols[idx].column = crlf[i];
            cols[idx++].value = ptr;
        }
    }
    memset(lid, 0, sizeof(lid));
    (void)snprintf(flagn, sizeof(flagn), "%u", cf->flags);
    cols[idx].column = "flags";
    cols[idx++].value = flagn;
    (void)snprintf(lid, sizeof(lid), "%u", crl_id);
    cols[idx].column = "local_id";
    cols[idx++].value = lid;
    (void)snprintf(did, sizeof(did), "%u", cf->dirid);
    cols[idx].column = "dir_id";
    cols[idx++].value = did;
    (void)snprintf(csnlen, sizeof(csnlen), "%d", cf->snlen);
    cols[idx].column = "snlen";
    cols[idx++].value = csnlen;
    cols[idx].column = "sninuse";
    cols[idx++].value = csnlen;
    cols[idx].column = "snlist";
    cols[idx++].value = hexs;
    aone.vec = &cols[0];
    aone.ntot = CRF_NFIELDS + 6;
    aone.nused = idx;
    aone.vald = 0;
    // add the CRL
    sta = insertscm(conp, theCRLTable, &aone);
    free((void *)hexs);
    return (sta);
}

/*
 * Callback function used in verification. 
 */

static int cbx509err = 0;

static int verify_callback(
    int ok2,
    X509_STORE_CTX * store)
{
    if (!ok2)
    {
        cbx509err = store->error;
        LOG(LOG_ERR, "Error: %s",
                X509_verify_cert_error_string(cbx509err));
    }
    else
        cbx509err = 0;
    return (ok2);
}

/*
 * This function gets the sigval parameter from a table based on the type. It
 * returns one of the SIGVAL_ constants indicating what happened. 
 */

static int get_cert_sigval(
    scmcon * conp,
    char *subj,
    char *ski)
{
    static scmsrcha *sigsrch = NULL;
    unsigned int *svalp;
    int sval;
    int sta = 0;

    if (theSCMP != NULL)
        initTables(theSCMP);
    if (sigsrch == NULL)
    {
        sigsrch = newsrchscm(NULL, 1, 0, 1);
        ADDCOL(sigsrch, "sigval", SQL_C_ULONG, sizeof(unsigned int), sta,
               SIGVAL_UNKNOWN);
    }
    (void)snprintf(sigsrch->wherestr, WHERESTR_SIZE,
                   "ski=\"%s\" and subject=\"%s\"", ski, subj);
    // (void)printf("Wherestr = %s\n", sigsrch->wherestr);
    sta = searchscm(conp, theCertTable, sigsrch, NULL, ok,
                    SCM_SRCH_DOVALUE_ALWAYS, NULL);
    // (void)printf("Sta = %d\n", sta);
    if (sta < 0)
        return SIGVAL_UNKNOWN;
    svalp = (unsigned int *)(sigsrch->vec[0].valptr);
    if (svalp == NULL)
        return SIGVAL_UNKNOWN;
    sval = *(int *)svalp;
    // (void)printf("Sval = %d\n", sta);
    if (sval < SIGVAL_UNKNOWN || sval > SIGVAL_INVALID)
        return SIGVAL_UNKNOWN;
    return sval;
}

static int get_roa_sigval(
    scmcon * conp,
    char *ski)
{
    static scmsrcha *sigsrch = NULL;
    unsigned int *svalp;
    int sval;
    int sta = 0;

    if (theSCMP != NULL)
        initTables(theSCMP);
    if (sigsrch == NULL)
    {
        sigsrch = newsrchscm(NULL, 1, 0, 1);
        ADDCOL(sigsrch, "sigval", SQL_C_ULONG, sizeof(unsigned int), sta,
               SIGVAL_UNKNOWN);
    }
    (void)snprintf(sigsrch->wherestr, WHERESTR_SIZE, "ski=\"%s\"", ski);
    // (void)printf("Wherestr = %s\n", sigsrch->wherestr);
    sta = searchscm(conp, theROATable, sigsrch, NULL, ok,
                    SCM_SRCH_DOVALUE_ALWAYS, NULL);
    // (void)printf("Sta = %d\n", sta);
    if (sta < 0)
        return SIGVAL_UNKNOWN;
    svalp = (unsigned int *)(sigsrch->vec[0].valptr);
    if (svalp == NULL)
        return SIGVAL_UNKNOWN;
    sval = *(int *)svalp;
    // (void)printf("Sval = %d\n", sta);
    if (sval < SIGVAL_UNKNOWN || sval > SIGVAL_INVALID)
        return SIGVAL_UNKNOWN;
    return sval;
}

static int get_sigval(
    scmcon * conp,
    int typ,
    char *item1,
    char *item2)
{
    switch (typ)
    {
    case OT_CER:
        return get_cert_sigval(conp, item1, item2);
    case OT_ROA:
        return get_roa_sigval(conp, item1);
        // other cases not handled yet
    default:
        break;
    }
    return SIGVAL_UNKNOWN;
}

/*
 * This function attempts to set the sigval parameter in a table based on the
 * type. It has no return value, since the only negative effect it can have is 
 * on performance. 
 */

static int set_cert_sigval(
    scmcon * conp,
    char *subj,
    char *ski,
    int valu)
{
    char stmt[520];
    int sta;

    if (theSCMP != NULL)
        initTables(theSCMP);
    if (theCertTable == NULL)
        return ERR_SCM_NOSUCHTAB;
    char escaped_subj[2 * strlen(subj) + 1];
    mysql_escape_string(escaped_subj, subj, strlen(subj));
    (void)snprintf(stmt, sizeof(stmt),
                   "update %s set sigval=%d where ski=\"%s\" and subject=\"%s\";",
                   theCertTable->tabname, valu, ski, escaped_subj);
    // (void)printf("SET: %s\n", stmt);
    sta = statementscm_no_data(conp, stmt);
    // (void)printf("Statementscn returns %d\n", sta);
    return sta;
}

static int set_roa_sigval(
    scmcon * conp,
    char *ski,
    int valu)
{
    char stmt[520];
    int sta;

    if (theSCMP != NULL)
        initTables(theSCMP);
    if (theROATable == NULL)
        return ERR_SCM_NOSUCHTAB;
    (void)snprintf(stmt, sizeof(stmt),
                   "update %s set sigval=%d where ski=\"%s\";",
                   theROATable->tabname, valu, ski);
    // (void)printf("SET: %s\n", stmt);
    sta = statementscm_no_data(conp, stmt);
    // (void)printf("Statementscn returns %d\n", sta);
    return sta;
}

static int set_sigval(
    scmcon * conp,
    int typ,
    char *item1,
    char *item2,
    int valu)
{
    int sta = -1;

    switch (typ)
    {
    case OT_CER:
        sta = set_cert_sigval(conp, item1, item2, valu);
        break;
    case OT_ROA:
        sta = set_roa_sigval(conp, item1, valu);
        break;
    default:
        // other cases not handled yet
        break;
    }
    return sta;
}

/*
 * A verification function type 
 */

typedef int (
    *vfunc) (
    X509_STORE_CTX *);

/*
 * Global variables used by the verification callback 
 */

static vfunc old_vfunc = NULL;
static scmcon *thecon = NULL;

/*
 * Our replacement for X509_verify. Consults the database first to see if the
 * certificate is already valid, otherwise calls X509_verify and then sets the 
 * state in the db based on that. It returns 1 on success and 0 on failure. 
 */

static int local_verify(
    X509 * cert,
    EVP_PKEY * pkey)
{
    int x509sta = 0;
    int sta = 0;
    int sigval = SIGVAL_UNKNOWN;
    int mok;
    char *subj = NULL;
    char *ski = NULL;

    // (void)printf("LOCAL VERIFY!\n");
    // first, get the subject and the SKI
    subj = X509_to_subject(cert, &sta, &x509sta);
    if (subj != NULL)
    {
        ski = X509_to_ski(cert, &sta, &x509sta);
        if (ski != NULL)
        {
            sigval = get_sigval(thecon, OT_CER, subj, ski);
            // (void)printf("Sigval from db: %d\n", sigval);
        }
    }
    switch (sigval)
    {
    case SIGVAL_VALID:         /* already validated */
        if (subj != NULL)
            free((void *)subj);
        if (ski != NULL)
            free((void *)ski);
        return 1;
    case SIGVAL_INVALID:       /* already invalidated */
        if (subj != NULL)
            free((void *)subj);
        if (ski != NULL)
            free((void *)ski);
        return 0;
    case SIGVAL_UNKNOWN:
    case SIGVAL_NOTPRESENT:
    default:
        break;                  /* compute validity, then set in db */
    }
    mok = X509_verify(cert, pkey);
    if (mok)
    {
        // (void)printf("Sigval to db: %d\n", SIGVAL_VALID);
        set_sigval(thecon, OT_CER, subj, ski, SIGVAL_VALID);
    }
    if (subj != NULL)
        free((void *)subj);
    if (ski != NULL)
        free((void *)ski);
    return mok;
}

/*
 * Our own internal verifier, replacing the internal_verify function in
 * openSSL (x509_vfy.c). It returns 1 on success and 0 on failure. 
 */

static int our_verify(
    X509_STORE_CTX * ctx)
{
    int mok;
    int n;
    int (
    *cb) (
    int,
    X509_STORE_CTX *);
    X509 *xsubject;
    X509 *xissuer;
    EVP_PKEY *pkey = NULL;

    // (void)printf("OUR VERIFY!\n");
    cb = ctx->verify_cb;
    n = sk_X509_num(ctx->chain);
    // (void)printf("NUM is %d\n", n);
    ctx->error_depth = n - 1;
    n--;
    xissuer = sk_X509_value(ctx->chain, n);
    if (ctx->check_issued(ctx, xissuer, xissuer))
        xsubject = xissuer;
    else
    {
        if (n <= 0)
        {
            ctx->error = X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE;
            ctx->current_cert = xissuer;
            mok = cb(0, ctx);
            goto end;
        }
        else
        {
            n--;
            ctx->error_depth = n;
            xsubject = sk_X509_value(ctx->chain, n);
        }
    }
    while (n >= 0)
    {
        ctx->error_depth = n;
        if (!xsubject->valid)
        {
            pkey = X509_get_pubkey(xissuer);
            if (pkey == NULL)
            {
                ctx->error = X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
                ctx->current_cert = xissuer;
                mok = cb(0, ctx);
                if (!mok)
                    goto end;
            }
            else if (local_verify(xsubject, pkey) <= 0)
            {
                ctx->error = X509_V_ERR_CERT_SIGNATURE_FAILURE;
                ctx->current_cert = xsubject;
                mok = cb(0, ctx);
                if (!mok)
                {
                    EVP_PKEY_free(pkey);
                    goto end;
                }
            }
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }
        xsubject->valid = 1;
        /*
         * mok = check_cert_time(ctx, xsubject); if ( !mok ) goto end; 
         */
        ctx->current_issuer = xissuer;
        ctx->current_cert = xsubject;
        mok = cb(1, ctx);
        if (!mok)
            goto end;
        n--;
        if (n >= 0)
        {
            xissuer = xsubject;
            xsubject = sk_X509_value(ctx->chain, n);
        }
    }
    mok = 1;
  end:
    return mok;
}

/******************************************************
 * static int checkit(conp, cert_ctx, x, sk_untrusted,      *
 *                     sk_trusted, purpose, NULL)     *
 *   This is the routine that actually calls          *
 *     X509_verify_cert(). Prior to calling the final *
 *     verify function it performs the following      *
 *     steps(+):                                      *
 *                                                    *
 *     creates an X509_STORE_CTX                      *
 *     sets the flags to 0                            *
 *     initializes the CTX with the X509_STORE,       *
 *         X509 cert being checked, and the stack     *
 *         of untrusted X509 certs                    *
 *     sets the trusted stack of X509 certs in the CTX*
 *     sets the purpose in the CTX (which we had      *
 *       set outside of this function to the OpenSSL  *
 *       definition of "any")                         *
 *     calls X509_verify_cert                         *
 *                                                    *
 *  This function is modified from check() in         *
 *  apps/verify.c of the OpenSSL source               *
 ******************************************************/

static int checkit(
    scmcon * conp,
    X509_STORE * ctx,
    X509 * x,
    STACK_OF(X509) * uchain,
    STACK_OF(X509) * tchain,
    int purpose,
    ENGINE * e)
{
    X509_STORE_CTX *csc;
    int i;

    UNREFERENCED_PARAMETER(e);
    csc = X509_STORE_CTX_new();
    if (csc == NULL)
        return (ERR_SCM_STORECTX);
    X509_STORE_set_flags(ctx, 0);
    if (!X509_STORE_CTX_init(csc, ctx, x, uchain))
    {
        X509_STORE_CTX_free(csc);
        return (ERR_SCM_STOREINIT);
    }
    if (tchain != NULL)
        X509_STORE_CTX_trusted_stack(csc, tchain);
    if (purpose >= 0)
        X509_STORE_CTX_set_purpose(csc, purpose);
    old_vfunc = ctx->verify;
    thecon = conp;
    // (void)printf("Checkit: Here\n");
    csc->verify = our_verify;
    i = X509_verify_cert(csc);
    csc->verify = old_vfunc;
    old_vfunc = NULL;
    thecon = NULL;
    X509_STORE_CTX_free(csc);
    if (i)
        return (0);             /* verified ok */
    else
        return (ERR_SCM_NOTVALID);
}

/*
 * Read cert data from a file
 * Unlike cert2fields, this just fills in the X509 structure,
 *  not the certfields
 */

static X509 *readCertFromFile(
    char *ofullname,
    int *stap)
{
    X509 *px = NULL;
    BIO *bcert = NULL;
    int typ,
        x509sta;

    // open the file
    typ = infer_filetype(ofullname);
    bcert = BIO_new(BIO_s_file());
    if (bcert == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        return (NULL);
    }
    x509sta = BIO_read_filename(bcert, ofullname);
    if (x509sta <= 0)
    {
        BIO_free_all(bcert);
        *stap = ERR_SCM_X509;
        return (NULL);
    }
    // read the cert based on the input type
    if (typ < OT_PEM_OFFSET)
        px = d2i_X509_bio(bcert, NULL);
    else
        px = PEM_read_bio_X509_AUX(bcert, NULL, NULL, NULL);
    BIO_free_all(bcert);
    if (px == NULL)
        *stap = ERR_SCM_BADCERT;
    else
        *stap = 0;
    return (px);
}

static scmsrcha *certSrch = NULL;

struct cert_answers cert_answers;

static int addCert2List(
    scmcon * conp,
    scmsrcha * s,
    int idx)
{
    UNREFERENCED_PARAMETER(conp);
    UNREFERENCED_PARAMETER(idx);
    if (!cert_answers.num_ansrs)
        cert_answers.cert_ansrp =
            (struct cert_ansr *)calloc(1, sizeof(struct cert_ansr));
    else
        cert_answers.cert_ansrp =
            (struct cert_ansr *)realloc(cert_answers.cert_ansrp,
                                        sizeof(struct cert_ansr) *
                                        (cert_answers.num_ansrs + 1));
    struct cert_ansr *this_ansrp =
        &cert_answers.cert_ansrp[cert_answers.num_ansrs++];
    memset(this_ansrp->dirname, 0, sizeof(this_ansrp->dirname));
    strcpy(this_ansrp->dirname, (char *)certSrch->vec[1].valptr);
    memset(this_ansrp->filename, 0, sizeof(this_ansrp->filename));
    strcpy(this_ansrp->filename, (char *)certSrch->vec[0].valptr);
    memset(this_ansrp->fullname, 0, sizeof(this_ansrp->fullname));
    snprintf(this_ansrp->fullname, PATH_MAX, "%s/%s",
             (char *)certSrch->vec[1].valptr, (char *)certSrch->vec[0].valptr);
    memset(this_ansrp->issuer, 0, sizeof(this_ansrp->issuer));
    strcpy(this_ansrp->issuer, (char *)certSrch->vec[4].valptr);
    memset(this_ansrp->aki, 0, sizeof(this_ansrp->aki));
    strcpy(this_ansrp->aki, (char *)certSrch->vec[3].valptr);
    this_ansrp->flags = *(unsigned int *)s->vec[2].valptr;
    this_ansrp->local_id = *(unsigned int *)s->vec[5].valptr;
    return 0;
}

/*
 * Get the parent certificate by using the issuer and the aki of "x" to look
 * it up in the db. If "x" has already been broken down in "cf" just use the
 * issuer/aki from there, otherwise look it up from "x". The db lookup will
 * return the filename and directory name of the parent cert, as well as its
 * flags. Set those flags into "pflags" 
 */

// static variables for efficiency, so only need to set up query once

static scmsrcha *parentSrch = NULL;
static char *parentDir,
   *parentFile;
static unsigned int *parentFlags;
static char *parentAKI,
   *parentIssuer;

struct cert_answers *find_parent_cert(
    char *ski,
    char *subject,
    scmcon * conp)
{
    int sta;
    if (certSrch == NULL)
    {
        certSrch = newsrchscm(NULL, 6, 0, 1);
        ADDCOL(certSrch, "filename", SQL_C_CHAR, FNAMESIZE, sta, NULL);
        ADDCOL(certSrch, "dirname", SQL_C_CHAR, DNAMESIZE, sta, NULL);
        ADDCOL(certSrch, "flags", SQL_C_ULONG, sizeof(unsigned int),
               sta, NULL);
        ADDCOL(certSrch, "aki", SQL_C_CHAR, SKISIZE, sta, NULL);
        ADDCOL(certSrch, "issuer", SQL_C_CHAR, SUBJSIZE, sta, NULL);
        ADDCOL(certSrch, "local_id", SQL_C_ULONG, sizeof(unsigned int), sta,
               NULL);
        parentFile = (char *)certSrch->vec[0].valptr;
        parentDir = (char *)certSrch->vec[1].valptr;
        parentFlags = (unsigned int *)certSrch->vec[2].valptr;
        parentAKI = (char *)certSrch->vec[3].valptr;
        parentIssuer = (char *)certSrch->vec[4].valptr;
    }
    sta = 0;
    // find the entry whose subject is our issuer and whose ski is our aki,
    // e.g. our parent
    if (subject != NULL)
        snprintf(certSrch->wherestr, WHERESTR_SIZE,
                 "ski=\'%s\' and subject=\'%s\'", ski, subject);
    else
        snprintf(certSrch->wherestr, WHERESTR_SIZE, "ski=\'%s\'", ski);
    addFlagTest(certSrch->wherestr, SCM_FLAG_VALIDATED, 1, 1);
    addFlagTest(certSrch->wherestr, SCM_FLAG_NOCHAIN, 0, 1);
    cert_answers.num_ansrs = 0;
    if (cert_answers.cert_ansrp)
        free(cert_answers.cert_ansrp);
    cert_answers.cert_ansrp = NULL;
    sta = searchscm(conp, theCertTable, certSrch, NULL, addCert2List,
                    SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);
    if (sta < 0)
        cert_answers.num_ansrs = sta;
    return &cert_answers;
}

static X509 *parent_cert(
    scmcon * conp,
    char *ski,
    char *subject,
    int *stap,
    char **pathname,
    int *flagsp)
{
    char ofullname[PATH_MAX];   /* full pathname */

    struct cert_answers *cert_answersp = find_parent_cert(ski, subject, conp);
    struct cert_ansr *cert_ansrp = &cert_answersp->cert_ansrp[1];
    int ff = (SCM_FLAG_ISPARACERT | SCM_FLAG_HASPARACERT | SCM_FLAG_ISTARGET);
    if (!cert_answersp || cert_answersp->num_ansrs <= 0)
        return NULL;
    if (cert_answersp->num_ansrs == 1)
    {
        cert_ansrp = &cert_answersp->cert_ansrp[0];
        if (cert_ansrp->flags & (SCM_FLAG_ISTARGET | SCM_FLAG_HASPARACERT))
            return NULL;
    }
    else if (cert_answersp->num_ansrs == 2)
    {
        // do they conflict?
        if (((cert_answersp->cert_ansrp[0].flags & ff) &
             (cert_ansrp->flags & ff)))
            return NULL;
        // if using paracerts, choose the paracert

        if ((useParacerts &&
             (cert_answersp->cert_ansrp[0].flags & SCM_FLAG_ISPARACERT)) ||
            (!useParacerts &&
             !(cert_answersp->cert_ansrp[0].flags & SCM_FLAG_ISPARACERT)))
            cert_ansrp = &cert_answersp->cert_ansrp[0];
        if (!parentAKI || !parentIssuer)
            return NULL;
        strcpy(parentAKI, cert_ansrp->aki);
        strcpy(parentIssuer, cert_ansrp->issuer);
    }
    else
        return NULL;
    (void)snprintf(ofullname, PATH_MAX, "%s", cert_ansrp->fullname);
    if (pathname != NULL)
        strncpy(*pathname, ofullname, PATH_MAX);
    if (flagsp)
        *flagsp = cert_ansrp->flags;
    return readCertFromFile(ofullname, stap);
    if (*stap < 0)
        return NULL;
    return NULL;
}

struct cert_answers *find_cert_by_aKI(
    char *ski,
    char *aki,
    scm * scmp,
    scmcon * conp)
{
    int sta;
    initTables(scmp);
    if (certSrch == NULL)
    {
        certSrch = newsrchscm(NULL, 6, 0, 1);
        ADDCOL(certSrch, "filename", SQL_C_CHAR, FNAMESIZE, sta, NULL);
        ADDCOL(certSrch, "dirname", SQL_C_CHAR, DNAMESIZE, sta, NULL);
        ADDCOL(certSrch, "flags", SQL_C_ULONG, sizeof(unsigned int), sta,
               NULL);
        ADDCOL(certSrch, "ski", SQL_C_CHAR, SKISIZE, sta, NULL);
        ADDCOL(certSrch, "aki", SQL_C_CHAR, SKISIZE, sta, NULL);
        ADDCOL(certSrch, "local_id", SQL_C_ULONG, sizeof(unsigned int), sta,
               NULL);
    }
    sta = 0;
    if (ski)
        snprintf(certSrch->wherestr, WHERESTR_SIZE, "ski=\'%s\'", ski);
    else
        snprintf(certSrch->wherestr, WHERESTR_SIZE, "aki=\'%s\'", aki);
    addFlagTest(certSrch->wherestr, SCM_FLAG_VALIDATED, 1, 1);
    addFlagTest(certSrch->wherestr, SCM_FLAG_NOCHAIN, 0, 1);
    cert_answers.num_ansrs = 0;
    if (cert_answers.cert_ansrp)
        free(cert_answers.cert_ansrp);
    cert_answers.cert_ansrp = NULL;
    sta = searchscm(conp, theCertTable, certSrch, NULL, addCert2List,
                    SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);
    if (sta < 0)
        cert_answers.num_ansrs = sta;
    return &cert_answers;
}

struct cert_answers *find_trust_anchors(
    scm * scmp,
    scmcon * conp)
{
    int sta;
    initTables(scmp);
    // if (certSrch == NULL)
    // {
    certSrch = newsrchscm(NULL, 6, 0, 1);
    ADDCOL(certSrch, "filename", SQL_C_CHAR, FNAMESIZE, sta, NULL);
    ADDCOL(certSrch, "dirname", SQL_C_CHAR, DNAMESIZE, sta, NULL);
    ADDCOL(certSrch, "flags", SQL_C_ULONG, sizeof(unsigned int), sta, NULL);
    ADDCOL(certSrch, "ski", SQL_C_CHAR, SKISIZE, sta, NULL);
    ADDCOL(certSrch, "aki", SQL_C_CHAR, SKISIZE, sta, NULL);
    ADDCOL(certSrch, "local_id", SQL_C_ULONG, sizeof(unsigned int), sta, NULL);
    // }
    sta = 0;
    addFlagTest(certSrch->wherestr, SCM_FLAG_TRUSTED, 1, 0);
    cert_answers.num_ansrs = 0;
    sta = searchscm(conp, theCertTable, certSrch, NULL, addCert2List,
                    SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);
    if (sta < 0)
        cert_answers.num_ansrs = sta;
    return &cert_answers;
}

// static variables for efficiency, so only need to set up query once

static scmsrcha *revokedSrch = NULL;
static uint8_t *revokedSNList;
static unsigned int *revokedSNLen;

// static variables to pass to callback

static int isRevoked;
static uint8_t *revokedSN = NULL;

/*
 * callback function for cert_revoked 
 */

static int revokedHandler(
    scmcon * conp,
    scmsrcha * s,
    int numLine)
{
    UNREFERENCED_PARAMETER(conp);
    UNREFERENCED_PARAMETER(s);
    UNREFERENCED_PARAMETER(numLine);
    unsigned int i;
    for (i = 0; i < *revokedSNLen; i++)
    {
        if (memcmp(&revokedSNList[SER_NUM_MAX_SZ * i], revokedSN,
                   SER_NUM_MAX_SZ) == 0)
        {
            isRevoked = 1;
            break;
        }
    }
    return 0;
}

/*
 * Check whether a cert is revoked by a crl
 *
 * @return 0 if the cert isn't revoked, ERR_SCM_REVOKED if the cert is revoked,
 *         or other error code
 */

static int cert_revoked(
    scm * scmp,
    scmcon * conp,
    char *sn,
    char *issuer)
{
    int sta;
    int sn_len;

    // set up query once first time through and then just modify
    if (revokedSrch == NULL)
    {
        revokedSrch = newsrchscm(NULL, 2, 0, 1);
        initTables(scmp);
        ADDCOL(revokedSrch, "snlen", SQL_C_ULONG, sizeof(unsigned int),
               sta, sta);
        ADDCOL(revokedSrch, "snlist", SQL_C_BINARY, 16 * 1024 * 1024, sta,
               sta);
        revokedSNLen = (unsigned int *)revokedSrch->vec[0].valptr;
        revokedSNList = (uint8_t *)revokedSrch->vec[1].valptr;
    }
    // query for crls such that issuer = issuer, and flags & valid
    // and set isRevoked = 1 in the callback if sn is in snlist
    snprintf(revokedSrch->wherestr, WHERESTR_SIZE, "issuer=\"%s\"", issuer);
    addFlagTest(revokedSrch->wherestr, SCM_FLAG_VALIDATED, 1, 1);
    addFlagTest(revokedSrch->wherestr, SCM_FLAG_NOCHAIN, 0, 1);
    isRevoked = 0;
    sn_len = strlen(sn);
    if (sn_len != 2 + 2*SER_NUM_MAX_SZ) // "^x" followed by hex
    {
        return ERR_SCM_INVALARG;
    }
    revokedSN = unhexify(sn_len - 2, sn + 2); // 2 for the "^x" prefix
    if (revokedSN == NULL)
    {
        return ERR_SCM_NOMEM;
    }
    sta = searchscm(conp, theCRLTable, revokedSrch, NULL, revokedHandler,
                    SCM_SRCH_DOVALUE_ALWAYS, NULL);
    free(revokedSN);
    revokedSN = NULL;
    return isRevoked ? ERR_SCM_REVOKED : 0;
}

/*
 * Certificate verification code by mudge 
 */

static int verify_cert(
    scmcon * conp,
    X509 * x,
    int isTrusted,
    char *parentSKI,
    char *parentSubject,
    int *x509stap,
    int *chainOK)
{
    STACK_OF(X509) * sk_trusted = NULL;
    STACK_OF(X509) * sk_untrusted = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    X509_STORE *cert_ctx = NULL;
    X509_LOOKUP *lookup = NULL;
    X509_PURPOSE *xptmp = NULL;
    X509 *parent = NULL;
    int purpose,
        i;
    int sta = 0;

    // create X509 store
    cert_ctx = X509_STORE_new();
    if (cert_ctx == NULL)
        return (ERR_SCM_CERTCTX);
    // set the verify callback
    X509_STORE_set_verify_cb_func(cert_ctx, verify_callback);
    // initialize the purpose
    i = X509_PURPOSE_get_by_sname("any");
    xptmp = X509_PURPOSE_get0(i);
    purpose = X509_PURPOSE_get_id(xptmp);
    // setup the verification parameters
    vpm = (X509_VERIFY_PARAM *) X509_VERIFY_PARAM_new();
    X509_VERIFY_PARAM_set_purpose(vpm, purpose);
    X509_STORE_set1_param(cert_ctx, vpm);
    lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
    X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
    lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
    ERR_clear_error();
    // set up certificate stacks
    sk_trusted = sk_X509_new_null();
    if (sk_trusted == NULL)
    {
        X509_STORE_free(cert_ctx);
        X509_VERIFY_PARAM_free(vpm);
        return (ERR_SCM_X509STACK);
    }
    sk_untrusted = sk_X509_new_null();
    if (sk_untrusted == NULL)
    {
        sk_X509_free(sk_trusted);
        X509_STORE_free(cert_ctx);
        X509_VERIFY_PARAM_free(vpm);
        return (ERR_SCM_X509STACK);
    }
    // if the certificate has already been flagged as trusted
    // just push it on the trusted stack and verify it
    *chainOK = 0;
    if (isTrusted)
    {
        *chainOK = 1;
        sk_X509_push(sk_trusted, x);
    }
    else
    {
        int flags;
        parent =
            parent_cert(conp, parentSKI, parentSubject, &sta, NULL, &flags);
        while (parent != NULL)
        {
            if (flags & SCM_FLAG_TRUSTED)
            {
                *chainOK = 1;
                sk_X509_push(sk_trusted, parent);
                break;
            }
            else
            {
                sk_X509_push(sk_untrusted, parent);
                parent = parent_cert(conp, parentAKI, parentIssuer, &sta, NULL,
                                     &flags);
            }
        }
    }
    sta = 0;
    if (*chainOK)
        sta =
            checkit(conp, cert_ctx, x, sk_untrusted, sk_trusted, purpose,
                    NULL);
    *x509stap = cbx509err;
    sk_X509_pop_free(sk_untrusted, X509_free);
    sk_X509_pop_free(sk_trusted, X509_free);
    X509_STORE_free(cert_ctx);
    X509_VERIFY_PARAM_free(vpm);
    return (sta);
}

/*
 * crl verification code
 */

static int verify_crl(
    scmcon * conp,
    X509_CRL * x,
    char *parentSKI,
    char *parentSubject,
    int *x509sta,
    int *chainOK)
{
    int sta = 0;
    X509 *parent;
    EVP_PKEY *pkey;

    parent = parent_cert(conp, parentSKI, parentSubject, x509sta, NULL, NULL);
    if (parent == NULL)
    {
        *chainOK = 0;
        return 0;
    }
    *chainOK = 1;
    pkey = X509_get_pubkey(parent);
    sta = X509_CRL_verify(x, pkey);
    X509_free(parent);
    EVP_PKEY_free(pkey);
    return (sta <= 0) ? ERR_SCM_NOTVALID : 0;
}

/*
 * roa utility
 */

static unsigned char *readfile(
    char *fn,
    int *stap)
{
    struct stat mystat;
    char *outptr = NULL;
    char *ptr;
    int outsz = 0;
    int fd;
    int rd;

    if (stap == NULL)
        return (NULL);
    if (fn == NULL || fn[0] == 0)
    {
        *stap = ERR_SCM_INVALARG;
        return (NULL);
    }
    fd = open(fn, O_RDONLY);
    if (fd < 0)
    {
        *stap = ERR_SCM_COFILE;
        return (NULL);
    }
    memset(&mystat, 0, sizeof(mystat));
    if (fstat(fd, &mystat) < 0 || mystat.st_size == 0)
    {
        (void)close(fd);
        *stap = ERR_SCM_COFILE;
        return (NULL);
    }
    ptr = (char *)calloc(mystat.st_size, sizeof(char));
    if (ptr == NULL)
    {
        (void)close(fd);
        *stap = ERR_SCM_NOMEM;
        return (NULL);
    }
    rd = read(fd, ptr, mystat.st_size);
    (void)close(fd);
    if (rd != mystat.st_size)
    {
        free((void *)ptr);
        ptr = NULL;
        *stap = ERR_SCM_COFILE;
    }
    else
        *stap = 0;
    if (strstr(fn, ".pem") == NULL)     /* not a PEM file */
        return ((unsigned char *)ptr);
    *stap =
        decode_b64((unsigned char *)ptr, mystat.st_size,
                   (unsigned char **)&outptr, &outsz, "CERTIFICATE");
    free((void *)ptr);
    if (*stap < 0)
    {
        if (outptr != NULL)
        {
            free((void *)outptr);
            outptr = NULL;
        }
    }
    return ((unsigned char *)outptr);
}

/*
 * roa verification code
 */

static int verify_roa(
    scmcon * conp,
    struct ROA *r,
    char *ski,
    int *chainOK)
{
    unsigned char *blob = NULL;
    X509 *cert;
    int sta;
    char fn[PATH_MAX];
    char *fn2;

    // first, see if the ROA is already validated and in the DB
    // (void)printf("VERIFY_ROA\n");
    sta = get_sigval(conp, OT_ROA, ski, NULL);
    if (sta == SIGVAL_VALID)
    {
        // (void)printf("ALREADY validated this ROA!\n");
        *chainOK = 1;
        return 0;
    }
    // next call the syntactic verification
    sta = roaValidate(r);
    if (sta < 0)
        return (sta);
    fn2 = fn;
    cert = parent_cert(conp, ski, NULL, &sta, &fn2, NULL);
    if (cert == NULL)
    {
        *chainOK = 0;
        return 0;
    }
    *chainOK = 1;
    // read the ASN.1 blob from the file
    blob = readfile(fn, &sta);
    if (blob != NULL)
    {
        sta = roaValidate2(r);
        free((void *)blob);
    }
    X509_free(cert);
    // (void)printf("VERIFY_ROA %d\n", sta);
    if (sta >= 0)
    {
        sta = set_sigval(conp, OT_ROA, ski, NULL, SIGVAL_VALID);
        if (sta < 0)
            LOG(LOG_ERR,
                    "could not set ROA sigval: conp->mystat.errmsg = %s",
                    conp->mystat.errmsg);
    }
    return (sta < 0) ? sta : 0;
}

/*
 * utility function for setting and zeroing the flags dealing with validation
 * and validation staleness 
 */

static int updateValidFlags(
    scmcon * conp,
    scmtab * tabp,
    unsigned int id,
    unsigned int prevFlags,
    int isValid)
{
    char stmt[150];
    int flags = isValid ?
        ((prevFlags | SCM_FLAG_VALIDATED) & (~SCM_FLAG_NOCHAIN)) :
        (prevFlags | SCM_FLAG_NOCHAIN);
    snprintf(stmt, sizeof(stmt), "update %s set flags=%d where local_id=%d;",
             tabp->tabname, flags, id);
    return statementscm_no_data(conp, stmt);
}

// Used by rpwork
int set_cert_flag(
    scmcon * conp,
    unsigned int id,
    unsigned int flags)
{
    char stmt[150];
    snprintf(stmt, sizeof(stmt), "update %s set flags=%d where local_id=%d;",
             theCertTable->tabname, flags, id);
    return statementscm_no_data(conp, stmt);
}

static struct goodoid goodoids[3];

static int make_goodoids(
    )
{
    struct casn casn;
    simple_constructor(&casn, (ushort) 0, ASN_OBJ_ID);
    uchar oid[8];
    write_objid(&casn, id_cRLNumber);
    int lth = read_casn(&casn, oid);
    goodoids[0].oid = (uchar *) calloc(1, lth + 1);
    memcpy(goodoids[0].oid, oid, lth);
    goodoids[0].lth = lth;
    write_objid(&casn, id_authKeyId);
    lth = read_casn(&casn, oid);
    goodoids[1].oid = (uchar *) calloc(1, lth + 1);
    memcpy(goodoids[1].oid, oid, lth);
    goodoids[1].lth = lth;
    goodoids[2].lth = 0;
    goodoids[2].oid = NULL;
    delete_casn(&casn);
    return lth;
}

/*
 * callback function for verify_children
 */

static int verifyChildCRL(
    scmcon * conp,
    scmsrcha * s,
    int idx)
{
    crl_fields *cf;
    X509_CRL *x = NULL;
    int crlsta = 0;
    int sta = 0;
    unsigned int i,
        id;
    int typ,
        chainOK,
        x509sta;
    char pathname[PATH_MAX];

    UNREFERENCED_PARAMETER(idx);
    if (s->nused < 4)
        return ERR_SCM_INVALARG;

    if (!goodoids[0].lth)
        make_goodoids();
    // try verifying crl
    snprintf(pathname, PATH_MAX, "%s/%s", (char *)s->vec[0].valptr,
             (char *)s->vec[1].valptr);
    typ = infer_filetype(pathname);
    cf = crl2fields((char *)s->vec[1].valptr, pathname, typ,
                    &x, &sta, &crlsta, goodoids);
    if (cf == NULL)
        return sta;
    sta = verify_crl(conp, x, cf->fields[CRF_FIELD_AKI],
                     cf->fields[CRF_FIELD_ISSUER], &x509sta, &chainOK);
    id = *((unsigned int *)(s->vec[2].valptr));
    // if invalid, delete it
    if (sta < 0)
    {
        deletebylid(conp, theCRLTable, id);
        return sta;
    }
    // otherwise, validate it and do its revocations
    sta = updateValidFlags(conp, theCRLTable, id,
                           *((unsigned int *)(s->vec[3].valptr)), 1);
    for (i = 0; i < cf->snlen; i++)
    {
        model_cfunc(theSCMP, conp, cf->fields[CRF_FIELD_ISSUER],
                    cf->fields[CRF_FIELD_AKI],
                    &((uint8_t *)cf->snlist)[SER_NUM_MAX_SZ * i]);
    }
    return 0;
}

/*
 * callback function for verify_children
 */

static int verifyChildROA(
    scmcon * conp,
    scmsrcha * s,
    int idx)
{
    struct ROA roa;
    int typ,
        chainOK,
        sta;
    char pathname[PATH_MAX];
    char *skii;
    unsigned int id;

    UNREFERENCED_PARAMETER(idx);
    ROA(&roa, (ushort) 0);
    // try verifying crl
    snprintf(pathname, PATH_MAX, "%s/%s", (char *)s->vec[0].valptr,
             (char *)s->vec[1].valptr);
    typ = infer_filetype(pathname);
    sta =
        roaFromFile(pathname, typ >= OT_PEM_OFFSET ? FMT_PEM : FMT_DER, 1,
                    &roa);
    if (sta < 0)
        return sta;
    skii = (char *)roaSKI(&roa);
    sta = verify_roa(conp, &roa, skii, &chainOK);
    delete_casn(&roa.self);
    if (skii)
        free((void *)skii);
    id = *((unsigned int *)(s->vec[2].valptr));
    // if invalid, delete it
    if (sta < 0)
    {
        deletebylid(conp, theROATable, id);
        return sta;
    }
    // otherwise, validate it
    sta = updateValidFlags(conp, theROATable, id,
                           *((unsigned int *)(s->vec[3].valptr)), 1);
    return 0;
}

/*
 * set onman flag from all objects on newly validated manifest
 * plus, delete those objects with bad hashes
 */

static scmsrcha *updateManSrch = NULL;
static scmsrcha *updateManSrch2 = NULL;
static unsigned int updateManLid;
static char updateManPath[PATH_MAX];
static char updateManHash[HASHSIZE];

static int revoke_cert_and_children(
    scmcon * conp,
    scmsrcha * s,
    int idx);

static int handleUpdateMan(
    scmcon * conp,
    scmsrcha * s,
    int idx)
{
    (void)conp;
    (void)s;
    (void)idx;
    updateManLid = *((unsigned int *)updateManSrch->vec[1].valptr);
    snprintf(updateManPath, PATH_MAX, "%s/",
             (char *)updateManSrch->vec[0].valptr);
    snprintf(updateManHash, HASHSIZE, "%s",
             (char *)updateManSrch->vec[2].valptr);
    return 0;
}

static int updateManifestObjs(
    scmcon * conp,
    struct Manifest *manifest)
{
    struct FileAndHash *fahp = NULL;
    uchar file[NAME_MAX + 1];
    uchar escaped_file[NAME_MAX * 2 + 1];
    uchar bytehash[HASHSIZE / 2];
    uchar *bhash;
    scmtab *tabp;
    char flagStmt[200 + HASHSIZE];
    int bhashlen;
    int gothash;
    int sta;
    int fd;
    int len;

    // set up part of query
    if (updateManSrch == NULL)
    {
        updateManSrch = newsrchscm(NULL, 3, 0, 1);
        ADDCOL(updateManSrch, "dirname", SQL_C_CHAR, DNAMESIZE, sta, sta);
        ADDCOL(updateManSrch, "local_id", SQL_C_ULONG, sizeof(unsigned int),
               sta, sta);
        ADDCOL(updateManSrch, "hash", SQL_C_CHAR, HASHSIZE, sta, sta);
    }
    if (updateManSrch2 == NULL)
    {
        updateManSrch2 = newsrchscm(NULL, 4, 0, 1);
        ADDCOL(updateManSrch2, "local_id", SQL_C_ULONG, sizeof(unsigned int),
               sta, sta);
        ADDCOL(updateManSrch2, "ski", SQL_C_CHAR, SKISIZE, sta, sta);
        ADDCOL(updateManSrch2, "subject", SQL_C_CHAR, SUBJSIZE, sta, sta);
        ADDCOL(updateManSrch2, "flags", SQL_C_ULONG, sizeof(unsigned int),
               sta, sta);
    }
    // loop over files and hashes
    for (fahp = (struct FileAndHash *)member_casn(&manifest->fileList.self, 0);
         fahp != NULL; fahp = (struct FileAndHash *)next_of(&fahp->self))
    {
        if (vsize_casn(&fahp->file) + 1 > (int)sizeof(file))
        {
            return ERR_SCM_BADMFTFILENAME;
        }
        int flth = read_casn(&fahp->file, file);
        file[flth] = 0;
        if (strstr((char *)file, ".cer"))
            tabp = theCertTable;
        else if (strstr((char *)file, ".crl"))
            tabp = theCRLTable;
        else if (strstr((char *)file, ".roa"))
            tabp = theROATable;
        else
            continue;
        mysql_escape_string(escaped_file, file, strlen(file));
        snprintf(updateManSrch->wherestr, WHERESTR_SIZE, "filename=\"%s\"",
                 escaped_file);
        addFlagTest(updateManSrch->wherestr, SCM_FLAG_ONMAN, 0, 1);
        updateManLid = 0;
        memset(updateManHash, 0, sizeof(updateManHash));
        searchscm(conp, tabp, updateManSrch, NULL, handleUpdateMan,
                  SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);
        if (!updateManLid)
            continue;
        len = strlen(updateManPath);
        snprintf(updateManPath + len, PATH_MAX - len, "%s", file);
        fd = open(updateManPath, O_RDONLY);
        if (fd < 0)
            continue;
        /*
         * Note that the hash is stored in the db as a string, but the
         * function check_fileAndHash wants it as a byte array. 
         */
        if (updateManHash[0] != 0)
        {
            gothash = 1;
            bhashlen = strlen(updateManHash);
            bhash = unhexify(bhashlen, updateManHash);
            if (bhash == NULL)
                sta = ERR_SCM_BADMFTDBHASH;
            else
            {
                bhashlen /= 2;
                memcpy(bytehash, bhash, bhashlen);
                free((void *)bhash);
                sta =
                    check_fileAndHash(fahp, fd, bytehash, bhashlen,
                                      HASHSIZE / 2);
            }
        }
        else
        {
            gothash = 0;
            memset(bytehash, 0, sizeof(bytehash));
            sta = check_fileAndHash(fahp, fd, bytehash, 0, HASHSIZE / 2);
        }
        (void)close(fd);
        if (sta >= 0)
        {
            // if hash okay, set ONMAN flag and optionally the hash if we just 
            // computed it
            if (gothash == 1)
                snprintf(flagStmt, sizeof(flagStmt),
                         "update %s set flags=flags+%d where local_id=%d;",
                         tabp->tabname, SCM_FLAG_ONMAN, updateManLid);
            else
            {
                char *h = hexify(sta, bytehash, HEXIFY_NO);
                // (void)fprintf(stderr, "Updating hash of %s to %s\n", file,
                // h);
                snprintf(flagStmt, sizeof(flagStmt),
                         "update %s set flags=flags+%d, hash=\"%s\" where local_id=%d;",
                         tabp->tabname, SCM_FLAG_ONMAN, h, updateManLid);
                free((void *)h);
            }
            statementscm_no_data(conp, flagStmt);
        }
        else
        {
            LOG(LOG_ERR, "Hash not ok on file %s", file);
            // if hash not okay, delete object, and if cert, invalidate
            // children
            if (tabp == theCertTable)
            {
                snprintf(updateManSrch2->wherestr, WHERESTR_SIZE,
                         "local_id=\"%d\"", updateManLid);
                searchscm(conp, tabp, updateManSrch2, NULL,
                          revoke_cert_and_children, SCM_SRCH_DOVALUE_ALWAYS,
                          NULL);
            }
            else
            {
                deletebylid(conp, tabp, updateManLid);
            }
        }
    }
    return 0;
}

/*
 * callback function for verify_children
 */

static int verifyChildManifest(
    scmcon * conp,
    scmsrcha * s,
    int idx)
{
    int sta;
    struct ROA roa;
    char outfull[PATH_MAX];
    UNREFERENCED_PARAMETER(idx);
    sta = updateValidFlags(conp, theManifestTable,
                           *((unsigned int *)(s->vec[0].valptr)),
                           *((unsigned int *)(s->vec[1].valptr)), 1);
    ROA(&roa, 0);
    snprintf(outfull, PATH_MAX, "%s/%s", (char *)(s->vec[2].valptr),
             (char *)(s->vec[3].valptr));
    sta = get_casn_file(&roa.self, outfull, 0);
    if (sta < 0)
    {
        delete_casn(&roa.self);
        LOG(LOG_ERR, "invalid manifest filename %s", outfull);
        return sta;
    }
    struct Manifest *manifest =
        &roa.content.signedData.encapContentInfo.eContent.manifest;
    sta = updateManifestObjs(conp, manifest);
    delete_casn(&roa.self);
    return 0;
}

// structure containing data of children to propagate

typedef struct _PropData {
    char *ski;
    char *subject;
    unsigned int flags;
    unsigned int id;
    char *filename;
    char *dirname;
    char *aki;
    char *issuer;
} PropData;

// static variables for efficiency, so only need to set up query once

static scmsrcha *crlSrch = NULL;
static scmsrcha *manSrch = NULL;

// single place to allocate large amount of space for manifest files lists

static char manFiles[MANFILES_SIZE];

/*
 * utility function for verifyChildren
 */

static int verifyChildCert(
    scmcon * conp,
    PropData * data,
    int doVerify)
{
    X509 *x = NULL;
    int x509sta,
        sta,
        chainOK;
    char pathname[PATH_MAX];

    if (doVerify)
    {
        snprintf(pathname, PATH_MAX, "%s/%s", data->dirname, data->filename);
        x = readCertFromFile(pathname, &sta);
        if (x == NULL)
            return ERR_SCM_X509;
        sta =
            verify_cert(conp, x, 0, data->aki, data->issuer, &x509sta,
                        &chainOK);
        if (sta < 0)
        {
            LOG(LOG_ERR, "Child cert %s had bad signature", pathname);
            deletebylid(conp, theCertTable, data->id);
            return sta;
        }
        updateValidFlags(conp, theCertTable, data->id, data->flags, 1);
    }

    /* Check for subordinate CRLs */
    if (crlSrch == NULL)
    {
        crlSrch = newsrchscm(NULL, 4, 0, 1);
        ADDCOL(crlSrch, "dirname", SQL_C_CHAR, DNAMESIZE, sta, sta);
        ADDCOL(crlSrch, "filename", SQL_C_CHAR, FNAMESIZE, sta, sta);
        ADDCOL(crlSrch, "local_id", SQL_C_ULONG, sizeof(unsigned int),
               sta, sta);
        ADDCOL(crlSrch, "flags", SQL_C_ULONG, sizeof(unsigned int), sta, sta);
    }
    snprintf(crlSrch->wherestr, WHERESTR_SIZE,
             "aki=\"%s\" and issuer=\"%s\"", data->ski, data->subject);
    addFlagTest(crlSrch->wherestr, SCM_FLAG_NOCHAIN, 1, 1);
    sta = searchscm(conp, theCRLTable, crlSrch, NULL, verifyChildCRL,
                    SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);

    /* Check for associated ROA */
    snprintf(crlSrch->wherestr, WHERESTR_SIZE, "ski=\"%s\"", data->ski);
    addFlagTest(crlSrch->wherestr, SCM_FLAG_NOCHAIN, 1, 1);
    sta = searchscm(conp, theROATable, crlSrch, NULL, verifyChildROA,
                    SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);

    /* Check for associated Manifest */
    if (manSrch == NULL)
    {
        manSrch = newsrchscm(NULL, 4, 0, 1);
        ADDCOL(manSrch, "local_id", SQL_C_ULONG, sizeof(unsigned int),
               sta, sta);
        ADDCOL(manSrch, "flags", SQL_C_ULONG, sizeof(unsigned int), sta, sta);
        ADDCOL(manSrch, "dirname", SQL_C_CHAR, DNAMESIZE, sta, sta);
        ADDCOL(manSrch, "filename", SQL_C_CHAR, FNAMESIZE, sta, sta);
    }
    snprintf(manSrch->wherestr, WHERESTR_SIZE, "ski=\"%s\"", data->ski);
    sta = searchscm(conp, theManifestTable, manSrch, NULL, verifyChildManifest,
                    SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);
    return 0;
}

typedef struct _mcf {
    int did;
    int toplevel;
} mcf;


/*
 * This function returns the number of valid certificates that have subject=IS 
 * and ski=AK, or a negative error code on failure. 
 */

static int cparents(
    scmcon * conp,
    scmsrcha * s,
    int idx)
{
    UNREFERENCED_PARAMETER(conp);
    UNREFERENCED_PARAMETER(idx);
    mcf *mymcf = (mcf *) (s->context);
    // ???????????? don't have this function, instead use where clause ?????
    mymcf->did++;
    return (0);
}

static int countvalidparents(
    scmcon * conp,
    char *IS,
    char *AK)
{
    // ?????? replace this with shorter version using utility funcs ????????
    unsigned int flags = 0;
    scmsrcha srch;
    scmsrch srch1;
    scmkva where;
    scmkv w[2];
    mcf mymcf;
    char ws[256];
    char *now;
    int sta;

    w[0].column = "ski";
    w[0].value = AK;
    if (IS != NULL)
    {
        w[1].column = "subject";
        w[1].value = IS;
    }
    where.vec = &w[0];
    where.ntot = (IS == NULL) ? 1 : 2;
    where.nused = (IS == NULL) ? 1 : 2;
    where.vald = 0;
    srch1.colno = 1;
    srch1.sqltype = SQL_C_ULONG;
    srch1.colname = "flags";
    srch1.valptr = (void *)&flags;
    srch1.valsize = sizeof(unsigned int);
    srch1.avalsize = 0;
    srch.vec = &srch1;
    srch.sname = NULL;
    srch.ntot = 1;
    srch.nused = 1;
    srch.vald = 0;
    srch.where = &where;
    now = LocalTimeToDBTime(&sta);
    if (now == NULL)
        return (sta);
    snprintf(ws, sizeof(ws), "valfrom < \"%s\" AND \"%s\" < valto", now, now);
    free((void *)now);
    addFlagTest(ws, SCM_FLAG_VALIDATED, 1, 1);
    addFlagTest(ws, SCM_FLAG_NOCHAIN, 0, 1);
    srch.wherestr = &ws[0];
    mymcf.did = 0;
    srch.context = (void *)&mymcf;
    sta = searchscm(conp, theCertTable, &srch, NULL, cparents,
                    SCM_SRCH_DOVALUE_ALWAYS, NULL);
    if (sta < 0)
        return (sta);
    return mymcf.did;
}

// static variables for efficiency, so only need to set up query once

static scmsrcha *roaSrch = NULL;

/*
 * callback function for invalidateChildCert
 */

static int revoke_roa(
    scmcon * conp,
    scmsrcha * s,
    int idx)
{
    unsigned int lid,
        flags;
    char ski[512];

    UNREFERENCED_PARAMETER(idx);
    lid = *(unsigned int *)(s->vec[0].valptr);
    flags = *(unsigned int *)(s->vec[2].valptr);
    (void)strncpy(ski, (char *)(s->vec[1].valptr), 512);
    if (countvalidparents(conp, NULL, ski) > 0)
        return (0);
    updateValidFlags(conp, theROATable, lid, flags, 0);
    return 0;
}

/*
 * utility function for verify_children
 */

static int invalidateChildCert(
    scmcon * conp,
    PropData * data,
    int doUpdate)
{
    int sta;

    if (doUpdate)
    {
        if (countvalidparents(conp, data->issuer, data->aki) > 0)
            return -1;
        sta = updateValidFlags(conp, theCertTable, data->id, data->flags, 0);
        if (sta < 0)
            return sta;
    }
    if (roaSrch == NULL)
    {
        roaSrch = newsrchscm(NULL, 3, 0, 1);
        ADDCOL(roaSrch, "local_id", SQL_C_ULONG, sizeof(unsigned int), sta,
               sta);
        ADDCOL(roaSrch, "ski", SQL_C_CHAR, SKISIZE, sta, sta);
        ADDCOL(roaSrch, "flags", SQL_C_ULONG, sizeof(unsigned int), sta, sta);
    }
    snprintf(roaSrch->wherestr, WHERESTR_SIZE, "ski=\"%s\"", data->ski);
    addFlagTest(roaSrch->wherestr, SCM_FLAG_NOCHAIN, 0, 1);
    searchscm(conp, theROATable, roaSrch, NULL, revoke_roa,
              SCM_SRCH_DOVALUE_ALWAYS, NULL);
    return 0;
}

// static variables for efficiency, so only need to set up query once

static scmsrcha *childrenSrch = NULL;

// static variables and structure to pass back from callback and hold data

typedef struct _PropDataList {
    int size;
    int maxSize;
    PropData *data;
} PropDataList;

PropDataList vPropData = { 0, 200, NULL };
PropDataList iPropData = { 0, 200, NULL };

PropDataList *currPropData = NULL;
PropDataList *prevPropData = NULL;

/*
 * callback function for verify_children
 */

static int registerChild(
    scmcon * conp,
    scmsrcha * s,
    int idx)
{
    PropData *propData;

    UNREFERENCED_PARAMETER(s);
    UNREFERENCED_PARAMETER(conp);
    UNREFERENCED_PARAMETER(idx);
    // push onto stack of children to propagate
    if (currPropData->size == currPropData->maxSize)
    {
        currPropData->maxSize *= 2;
        propData =
            (PropData *) calloc(currPropData->maxSize, sizeof(PropData));
        memcpy(propData, currPropData->data,
               currPropData->size * sizeof(PropData));
        free(currPropData->data);
        currPropData->data = propData;
    }
    else
    {
        propData = currPropData->data;
    }
    propData[currPropData->size].dirname = strdup(s->vec[0].valptr);
    propData[currPropData->size].filename = strdup(s->vec[1].valptr);
    propData[currPropData->size].flags = *((unsigned int *)(s->vec[2].valptr));
    propData[currPropData->size].ski = strdup(s->vec[3].valptr);
    propData[currPropData->size].subject = strdup(s->vec[4].valptr);
    propData[currPropData->size].id = *((unsigned int *)(s->vec[5].valptr));
    propData[currPropData->size].aki = strdup(s->vec[6].valptr);
    propData[currPropData->size].issuer = strdup(s->vec[7].valptr);
    currPropData->size++;
    return 0;
}

/*
 * verify the children certs of the current cert
 */
static int verifyOrNotChildren(
    scmcon * conp,
    char *ski,
    char *subject,
    char *aki,
    char *issuer,
    unsigned int cert_id,
    int doVerify)
{
    int isRoot = 1;
    int doIt,
        idx,
        sta;

    prevPropData = currPropData;
    currPropData = doVerify ? &vPropData : &iPropData;

    // initialize query first time through
    if (childrenSrch == NULL)
    {
        childrenSrch = newsrchscm(NULL, 8, 0, 1);
        ADDCOL(childrenSrch, "dirname", SQL_C_CHAR, DNAMESIZE, sta, sta);
        ADDCOL(childrenSrch, "filename", SQL_C_CHAR, FNAMESIZE, sta, sta);
        ADDCOL(childrenSrch, "flags", SQL_C_ULONG, sizeof(unsigned int),
               sta, sta);
        ADDCOL(childrenSrch, "ski", SQL_C_CHAR, SKISIZE, sta, sta);
        ADDCOL(childrenSrch, "subject", SQL_C_CHAR, SUBJSIZE, sta, sta);
        ADDCOL(childrenSrch, "local_id", SQL_C_ULONG, sizeof(unsigned int),
               sta, sta);
        ADDCOL(childrenSrch, "aki", SQL_C_CHAR, SKISIZE, sta, sta);
        ADDCOL(childrenSrch, "issuer", SQL_C_CHAR, SUBJSIZE, sta, sta);
    }

    // iterate through all children, verifying
    if (currPropData->data == NULL)
        currPropData->data =
            (PropData *) calloc(currPropData->maxSize, sizeof(PropData));
    currPropData->data[0].ski = ski;
    currPropData->data[0].subject = subject;
    currPropData->data[0].aki = aki;
    currPropData->data[0].issuer = issuer;
    currPropData->data[0].id = cert_id;
    currPropData->size = 1;
    while (currPropData->size > 0)
    {
        currPropData->size--;
        idx = currPropData->size;
        if (doVerify)
            doIt =
                verifyChildCert(conp, &currPropData->data[idx], !isRoot) == 0;
        else
            doIt =
                invalidateChildCert(conp, &currPropData->data[idx],
                                    !isRoot) == 0;
        if (doIt)
        {
            snprintf(childrenSrch->wherestr, WHERESTR_SIZE,
                     "aki=\"%s\" and ski<>\"%s\" and issuer=\"%s\"",
                     currPropData->data[idx].ski, currPropData->data[idx].ski,
                     currPropData->data[idx].subject);
            addFlagTest(childrenSrch->wherestr, SCM_FLAG_NOCHAIN, doVerify, 1);
        }
        if (!isRoot)
        {
            free(currPropData->data[idx].filename);
            free(currPropData->data[idx].dirname);
            free(currPropData->data[idx].ski);
            free(currPropData->data[idx].subject);
            free(currPropData->data[idx].aki);
            free(currPropData->data[idx].issuer);
        }
        if (doIt)
            searchscm(conp, theCertTable, childrenSrch, NULL, registerChild,
                      SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);
        isRoot = 0;
    }
    currPropData = prevPropData;
    return 0;
}

/*
 * primarily, do check for whether there already is a valid manifest
 * that can either confirm or deny the hash
 */

static scmsrcha *validManSrch = NULL;
static char validManPath[PATH_MAX];

static int handleValidMan(
    scmcon * conp,
    scmsrcha * s,
    int idx)
{
    (void)conp;
    (void)idx;
    snprintf(validManPath, PATH_MAX, "%s/%s", (char *)s->vec[0].valptr,
             (char *)s->vec[1].valptr);
    return 0;
}

int addStateToFlags(
    unsigned int *flags,
    int isValid,
    char *filename,
    char *fullpath,
    scm * scmp,
    scmcon * conp)
{
    int sta,
        fd;
    struct ROA roa;
    struct casn ccasn;
    struct FileAndHash *fahp = NULL;

    *flags |= (isValid ? SCM_FLAG_VALIDATED : SCM_FLAG_NOCHAIN);
    if (fullpath == NULL)
        return 0;
    if (validManSrch == NULL)
    {
        validManSrch = newsrchscm(NULL, 2, 0, 1);
        ADDCOL(validManSrch, "dirname", SQL_C_CHAR, DNAMESIZE, sta, sta);
        ADDCOL(validManSrch, "filename", SQL_C_CHAR, FNAMESIZE, sta, sta);
    }
    snprintf(validManSrch->wherestr, WHERESTR_SIZE,
             "files regexp binary \"%s\"", filename);
    addFlagTest(validManSrch->wherestr, SCM_FLAG_VALIDATED, 1, 1);
    initTables(scmp);
    validManPath[0] = 0;
    searchscm(conp, theManifestTable, validManSrch, NULL, handleValidMan,
              SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);
    if (!validManPath[0])
        return 0;

    ROA(&roa, 0);
    sta = get_casn_file(&roa.self, validManPath, 0);
    struct Manifest *manifest =
        &roa.content.signedData.encapContentInfo.eContent.manifest;
    simple_constructor(&ccasn, (ushort) 0, ASN_IA5_STRING);
    write_casn(&ccasn, (uchar *) filename, strlen(filename));
    for (fahp = (struct FileAndHash *)member_casn(&manifest->fileList.self, 0);
         fahp && diff_casn(&fahp->file, &ccasn);
         fahp = (struct FileAndHash *)next_of(&fahp->self));
    sta = 0;
    if (fahp && (fd = open(fullpath, O_RDONLY)) >= 0)
    {
        *flags |= SCM_FLAG_ONMAN;
        sta = check_fileAndHash(fahp, fd, NULL, 0, 0);
        (void)close(fd);
    }
    delete_casn(&ccasn);
    delete_casn(&roa.self);
    return sta >= 0 ? 0 : sta;
}


/**=============================================================================
 * @brief Get an extension from a Cert, and a count of that type of extn.
 *
 * If multiple extensions of the given type are found, return the first one.
 *
 * @param certp (struct Certificate*)
 * @param idp (char*) an id pointer
 * @param count (int*) count of extensions of type id found
 * @retval extp a pointer to the extension<br />null on failure
------------------------------------------------------------------------------*/
struct Extension *get_extension(
    struct Certificate *certp,
    char *idp,
    int *count)
{
    struct Extensions *extsp = &certp->toBeSigned.extensions;
    struct Extension *extp = NULL;
    struct Extension *ret = NULL;
    int cnt = 0;

    for (extp = (struct Extension *)member_casn(&extsp->self, 0);
         extp != NULL; extp = (struct Extension *)next_of(&extp->self))
    {
        if (!diff_objid(&extp->extnID, idp))
        {
            if (!cnt)
                ret = extp;
            cnt++;
        }
    }

    if (count)
        *count = cnt;

    return ret;
}


/*
 * do the work of add_cert(). Factored out so we can call it from elsewhere.
 *
 * We should eventually merge this with add_cert_internal()
 *
 * Note: caller is responsible for invoking freecf(cf).
 */

static int add_cert_2(
    scm * scmp,
    scmcon * conp,
    cert_fields * cf,
    X509 * x,
    unsigned int id,
    int utrust,
    unsigned int *cert_id,
    char *fullpath)
{
    int sta = 0;
    int chainOK;
    int ct = UN_CERT;
    int x509sta = 0;

    cf->dirid = id;
    struct Certificate cert;
    Certificate(&cert, (ushort) 0);
    struct Extension *ski_extp,
       *aki_extp;
    int locerr = 0;
    if (get_casn_file(&cert.self, fullpath, 0) < 0)
        locerr = ERR_SCM_BADCERT;
    else if (!(ski_extp = find_extension(&cert.toBeSigned.extensions, id_subjectKeyIdentifier, false)))
        locerr = ERR_SCM_NOSKI;
    if (locerr)
    {
        delete_casn(&cert.self);
        return locerr;
    }
    if (utrust > 0)
    {
        if (((aki_extp = find_extension(&cert.toBeSigned.extensions, id_authKeyId, false)) &&
             diff_casn(&ski_extp->extnValue.subjectKeyIdentifier,
                       &aki_extp->extnValue.authKeyId.keyIdentifier)) ||
            strcmp(cf->fields[CF_FIELD_SUBJECT],
                   cf->fields[CF_FIELD_ISSUER]) != 0)
            locerr = 1;
        else if (vsize_casn(&cert.signature) < 256 ||
                 vsize_casn(&cert.toBeSigned.subjectPublicKeyInfo.
                            subjectPublicKey) < 265)
            locerr = ERR_SCM_SMALLKEY;
        if (locerr)
        {
            X509_free(x);
            delete_casn(&cert.self);
            return (locerr < 0) ? locerr : ERR_SCM_NOTSS;
        }
        cf->flags |= SCM_FLAG_TRUSTED;
    }
    // verify that the cert matches the rescert profile
    if (utrust > 0)
        ct = TA_CERT;
    else
        ct = (cf->flags & SCM_FLAG_CA) ? CA_CERT : EE_CERT;
    sta = rescert_profile_chk(x, &cert, ct);
    delete_casn(&cert.self);
    // MCR: new code to check for expiration. Ignore this
    // check if "allowex" is non-zero
    if ((sta == 0) && (allowex == 0))
    {
        if (X509_cmp_time(X509_get_notAfter(x), NULL) < 0)
            sta = ERR_SCM_EXPIRED;
    }
    // Check if cert isn't valid yet, i.e. notBefore is in the future.
    if (sta == 0)
    {
        if (X509_cmp_time(X509_get_notBefore(x), NULL) > 0)
        {
            LOG(LOG_WARNING, "Certificate notBefore is in the future");
            cf->flags |= SCM_FLAG_NOTYET;
        }
    }
    // MCR
    // verify the cert
    if (sta == 0)
    {
        sta = verify_cert(conp, x, utrust, cf->fields[CF_FIELD_AKI],
                          cf->fields[CF_FIELD_ISSUER], &x509sta, &chainOK);
    }
    // check that no crls revoking this cert
    if (sta == 0)
    {
        sta = cert_revoked(scmp, conp, cf->fields[CF_FIELD_SN],
                           cf->fields[CF_FIELD_ISSUER]);
    }
    // actually add the certificate
    // sta = 0; chainOK = 1; // uncomment this line for running test 8
    if (sta == 0)
    {
        sta =
            addStateToFlags(&cf->flags, chainOK, cf->fields[CF_FIELD_FILENAME],
                            fullpath, scmp, conp);
    }
    if (sta == 0)
    {
        sta = add_cert_internal(scmp, conp, cf, cert_id);
    }
    // try to validate children of cert
    if ((sta == 0) && chainOK)
    {
        sta = verifyOrNotChildren(conp, cf->fields[CF_FIELD_SKI],
                                  cf->fields[CF_FIELD_SUBJECT],
                                  cf->fields[CF_FIELD_AKI],
                                  cf->fields[CF_FIELD_ISSUER], *cert_id, 1);
    }
    // if change verify_cert so that not pushing on stack, change this
    if (!(cf->flags & SCM_FLAG_TRUSTED))
    {
        X509_free(x);
    }
    return (sta);
}

/*
 * Add a certificate to the DB. If utrust is set, check that it is self-signed 
 * first. Validate the cert and add it.
 * 
 * This function returns 0 on success and a negative error code on failure. 
 */

int add_cert(
    scm * scmp,
    scmcon * conp,
    char *outfile,
    char *outfull,
    unsigned int id,
    int utrust,
    int typ,
    unsigned int *cert_id,
    int constraining)
{
    cert_fields *cf;
    X509 *x = NULL;
    int x509sta = 0;
    int sta = 0;

    initTables(scmp);
    cf = cert2fields(outfile, outfull, typ, &x, &sta, &x509sta);
    if (cf == NULL || x == NULL)
    {
        if (cf != NULL)
            freecf(cf);
        if (x != NULL)
            X509_free(x);
        return (sta);
    }
    useParacerts = constraining;
    sta = add_cert_2(scmp, conp, cf, x, id, utrust, cert_id, outfull);
    freecf(cf);
    cf = NULL;
    return sta;
}

/*
 * Add a CRL to the DB.  This function returns 0 on success and a negative
 * error code on failure. 
 */

int add_crl(
    scm * scmp,
    scmcon * conp,
    char *outfile,
    char *outfull,
    unsigned int id,
    int utrust,
    int typ)
{
    crl_fields *cf;
    X509_CRL *x = NULL;
    int crlsta = 0;
    int sta = 0;
    unsigned int i;
    int chainOK,
        x509sta;
    struct CertificateRevocationList crl;

    if (!goodoids[0].lth)
        make_goodoids();
    UNREFERENCED_PARAMETER(utrust);

    // standalone profile check against draft-ietf-sidr-res-certs
    CertificateRevocationList(&crl, 0);
    if (get_casn_file(&crl.self, outfull, 0) < 0)
    {
        LOG(LOG_ERR, "Failed to load CRL: %s", outfile);
        delete_casn(&crl.self);
        return ERR_SCM_INVALASN;
    }
    if ((sta = crl_profile_chk(&crl)) != 0)
    {
        LOG(LOG_ERR, "CRL failed standalone profile check: %s", outfile);
        delete_casn(&crl.self);
        return sta;
    }
    delete_casn(&crl.self);

    cf = crl2fields(outfile, outfull, typ, &x, &sta, &crlsta, goodoids);
    if (cf == NULL || x == NULL)
    {
        if (cf != NULL)
            freecrf(cf);
        if (x != NULL)
            X509_CRL_free(x);
        return (sta);
    }
    cf->dirid = id;
    // first verify the CRL
    sta = verify_crl(conp, x, cf->fields[CRF_FIELD_AKI],
                     cf->fields[CRF_FIELD_ISSUER], &x509sta, &chainOK);
    // then add the CRL
    if (sta == 0)
    {
        sta =
            addStateToFlags(&cf->flags, chainOK,
                            cf->fields[CRF_FIELD_FILENAME], outfull, scmp,
                            conp);
    }
    if (sta == 0)
    {
        sta = add_crl_internal(scmp, conp, cf);
    }
    // and do the revocations
    if ((sta == 0) && chainOK)
    {
        uint8_t *u = (uint8_t *) cf->snlist;
        for (i = 0; i < cf->snlen; i++, u += SER_NUM_MAX_SZ)
        {
            model_cfunc(scmp, conp, cf->fields[CRF_FIELD_ISSUER],
                        cf->fields[CRF_FIELD_AKI], u);
        }
    }
    freecrf(cf);
    X509_CRL_free(x);
    return (sta);
}

static int hexify_ski(
    struct Certificate *certp,
    char *skip)
{
    struct Extension *extp = find_extension(&certp->toBeSigned.extensions,
                                            id_subjectKeyIdentifier, false);
    if (!extp)
        return ERR_SCM_NOSKI;
    int size = vsize_casn(&extp->self);
    uchar *tmp = calloc(1, size);
    read_casn(&extp->extnValue.self, tmp);      // read contents of outer
                                                // OCTET STRING
    struct casn theCASN;
    simple_constructor(&theCASN, 0, ASN_OCTETSTRING);
    decode_casn(&theCASN, tmp);
    size = read_casn(&theCASN, tmp);    // read contents of inner OCTET STRING
    delete_casn(&theCASN);
    char *str = skip;           // now hexify and punctuate it
    int i;
    for (i = 0; i < size; i++)
    {
        if (i)
            snprintf(str++, 2, ":");
        snprintf(str, 3, "%02X", tmp[i]);
        str += 2;
    }
    *str = 0;
    free(tmp);
    return size;
}

static int extractAndAddCert(
    struct ROA *roap,
    scm * scmp,
    scmcon * conp,
    char *outdir,
    int utrust,
    int typ,
    char *outfile,
    char *skip,
    char *certfilenamep)
{
    cert_fields *cf = NULL;
    unsigned int cert_id;
    char certname[PATH_MAX],
        pathname[PATH_MAX];
    int sta = 0;
    struct Certificate *certp;
    certp = (struct Certificate *)member_casn(&roap->content.signedData.
                                              certificates.self, 0);
    if (!certp)
        return ERR_SCM_BADNUMCERTS;
    if ((certp->self.flags & ASN_INDEF_LTH_FLAG))
        return ERR_SCM_ASN1_LTH;
    // read the embedded cert information, in particular the ski
    if ((sta = hexify_ski(certp, skip)) < 0)
        return sta;
    sta = 0;
    // test for forbidden extension
    struct Extension *extp;
    for (extp =
         (struct Extension *)member_casn(&certp->toBeSigned.extensions.self,
                                         0);
         extp && diff_objid(&extp->extnID, id_extKeyUsage);
         extp = (struct Extension *)next_of(&extp->self));
    if (extp)
        return ERR_SCM_BADEXT;
    // serialize the Certificate and scan it as an openssl X509 object
    int siz = size_casn(&certp->self);
    unsigned char *buf = calloc(1, siz + 4);
    siz = encode_casn(&certp->self, buf);
    /*
     * d2i_X509 changes "used" to point past end of the object 
     */
    unsigned char *used = buf;
    X509 *x509p = d2i_X509(NULL, (const unsigned char **)&used, siz);
    free(buf);
    // if deserialization failed, bail
    if (x509p == NULL || sta < 0)
        return ERR_SCM_X509;
    memset(certname, 0, sizeof(certname));
    memset(pathname, 0, sizeof(pathname));
    strcpy(certname, outfile);
    strcat(certname, ".cer");
    char *cc = retrieve_tdir(scmp, conp, &sta);
    // find or add the directory
    struct stat statbuf;
    strcat(strcpy(pathname, cc), "/EEcertificates");
    if (stat(pathname, &statbuf))
        mkdir(pathname, 0777);
    int lth = strlen(pathname) - 15;    // not counting /EEcertificates
    free((void *)cc);
    cc = &outdir[lth];

    if (*cc)
    {
        if (strncmp(outdir, pathname, lth))
            return ERR_SCM_WRITE_EE;
        cc = &outdir[lth];
        if (*cc == '/')
            strncat(pathname, cc++, 1);
        do
        {
            char *d = strchr(cc, '/');
            if (d)
            {
                d++;
                strncat(pathname, cc, d - cc);
            }
            else
                strcat(pathname, cc);
            cc = d;
            if (stat(pathname, &statbuf) < 0)
                mkdir(pathname, 0777);
        }
        while (cc);
    }
    else if (stat(pathname, &statbuf) < 0)
        mkdir(pathname, 0777);
    unsigned int dir_id;
    sta = findorcreatedir(scmp, conp, pathname, &dir_id);
    strcat(strcat(pathname, "/"), certname);
    if (certfilenamep)
        strcpy(certfilenamep, certname);
    // pull out the fields
    int x509sta;
    // write the cert there, because cert2fields needs that
    if (put_casn_file(&certp->self, pathname, 0) < 0)
        sta = ERR_SCM_WRITE_EE;
    else
        cf = cert2fields(certname, pathname, typ, &x509p, &sta, &x509sta);
    if (cf != NULL && sta == 0)
    {
        // add the X509 cert to the db with the right directory
        if (!cc)
        {
            cc = strrchr(pathname, (int)'/');
            strncpy(certname, pathname, (cc - pathname));
            certname[cc - pathname] = 0;
        }
        else
            strcpy(certname, outdir);
        sta = add_cert_2(scmp, conp, cf, x509p, dir_id, utrust, &cert_id,
                         pathname);
        if (typ == OT_ROA && sta == ERR_SCM_DUPSIG)
            sta = 0;            // dup roas OK
        else if (sta < 0)
        {
            LOG(LOG_ERR, "Error adding embedded certificate %s",
                    pathname);
            /*
             * Leave the file there for debugging purposes.  FIXME: add code
             * to clean this up later. 
             */
            // unlink(pathname);
        }
        else if (!sta && (cf->flags & SCM_FLAG_VALIDATED))
            sta = 1;
    }
    x509p = NULL;               /* freed by add_cert_2 */
    freecf(cf);
    cf = NULL;
    return sta;
}

static int add_roa_internal(
    scm * scmp,
    scmcon * conp,
    char *outfile,
    unsigned int dirid,
    char *ski,
    uint32_t asid,
    char *ip_addrs,
    char *sig,
    unsigned int flags)
{
    unsigned int roa_id = 0;
    scmkva aone;
    scmkv cols[8];
    char flagn[24];
    char asn[24];
    char lid[24];
    char did[24];
    int idx = 0;
    int sta;

    initTables(scmp);
    conp->mystat.tabname = "ROA";
    // first check for a duplicate signature
    sta = dupsigscm(scmp, conp, theROATable, sig);
    if (sta < 0)
        return (sta);
    sta = getmaxidscm(scmp, conp, "local_id", theROATable, &roa_id);
    if (sta < 0)
        return (sta);
    roa_id++;
    // fill in insertion structure
    cols[idx].column = "filename";
    cols[idx++].value = outfile;
    (void)snprintf(did, sizeof(did), "%u", dirid);
    cols[idx].column = "dir_id";
    cols[idx++].value = did;
    cols[idx].column = "ski";
    cols[idx++].value = ski;
    cols[idx].column = "sig";
    cols[idx++].value = sig;
    cols[idx].column = "ip_addrs";
    cols[idx++].value = ip_addrs;
    (void)snprintf(asn, sizeof(asn), "%" PRIu32, asid);
    cols[idx].column = "asn";
    cols[idx++].value = asn;
    (void)snprintf(flagn, sizeof(flagn), "%u", flags);
    cols[idx].column = "flags";
    cols[idx++].value = flagn;
    (void)snprintf(lid, sizeof(lid), "%u", roa_id);
    cols[idx].column = "local_id";
    cols[idx++].value = lid;
    aone.vec = &cols[0];
    aone.ntot = 8;
    aone.nused = idx;
    aone.vald = 0;
    // add the ROA
    sta = insertscm(conp, theROATable, &aone);
    return (sta);
}

/*
 * Add a ROA to the DB.  This function returns 0 on success and a negative
 * error code on failure. 
 */

int add_roa(
    scm * scmp,
    scmcon * conp,
    char *outfile,
    char *outdir,
    char *outfull,
    unsigned int id,
    int utrust,
    int typ)
{
    struct ROA roa;             // note: roaFromFile constructs this
    char ski[60],
       *sig = NULL,
        certfilename[PATH_MAX],
        *ip_addrs = NULL;
    unsigned char *bsig = NULL;
    int sta,
        chainOK,
        bsiglen = 0,
        cert_added = 0;
    uint32_t asid;
    unsigned int flags = 0;

    // validate parameters
    if (scmp == NULL || conp == NULL || conp->connected == 0 || outfile == NULL
        || outfile[0] == 0 || outfull == NULL || outfull[0] == 0)
        return (ERR_SCM_INVALARG);
    sta =
        roaFromFile(outfull, typ >= OT_PEM_OFFSET ? FMT_PEM : FMT_DER, 1,
                    &roa);
    if (sta < 0)
    {
        delete_casn(&roa.self);
        return (sta);
    }
    do
    {                           /* do-once */
        if ((sta = extractAndAddCert(&roa, scmp, conp, outdir,
                                     utrust, typ, outfile, ski,
                                     certfilename)) < 0)
            break;
        cert_added = 1;

        asid = roaAS_ID(&roa);  /* it's OK if this comes back zero */

        // signature NOTE: this does not calloc, only points
        if ((bsig = roaSignature(&roa, &bsiglen)) == NULL || bsiglen < 0)
        {
            sta = ERR_SCM_NOSIG;
            break;
        }

        if ((sig = hexify(bsiglen, bsig, HEXIFY_NO)) == NULL)
        {
            sta = ERR_SCM_NOMEM;
            break;
        }

        // verify the signature
        if ((sta = verify_roa(conp, &roa, ski, &chainOK)) != 0)
            break;

        // ip_addrs
        sta = roaGetIPAddresses(&roa, &ip_addrs);
        if (sta != 0)
            break;
        sta = addStateToFlags(&flags, chainOK, outfile, outfull, scmp, conp);
        if (sta != 0)
            break;

        // add to database
        sta = add_roa_internal(scmp, conp, outfile, id, ski, asid, ip_addrs,
                               sig, flags);
        if (sta < 0)
            break;

    } while (0);

    // clean up
    free(ip_addrs);
    if (sta != 0 && cert_added)
        (void)delete_object(scmp, conp, certfilename, outdir, outfull,
                            (unsigned int)0);
    delete_casn(&roa.self);
    if (sig != NULL)
        free(sig);
    return (sta);
}

/*
 * Add a manifest to the database 
 */

int add_manifest(
    scm * scmp,
    scmcon * conp,
    char *outfile,
    char *outdir,
    char *outfull,
    unsigned int id,
    int utrust,
    int typ)
{
    int sta,
        cert_added = 0,
        stale;
    struct ROA roa;
    char *thisUpdate,
       *nextUpdate,
        certfilename[PATH_MAX];
    char asn_time[16];          // DER GenTime: strlen("YYYYMMDDhhmmssZ") ==
                                // 15
    unsigned int man_id = 0;

    // manifest stored in same format as a roa
    ROA(&roa, 0);
    initTables(scmp);
    sta = get_casn_file(&roa.self, outfull, 0);
    if (sta < 0)
    {
        LOG(LOG_ERR, "invalid manifest %s", outfull);
        delete_casn(&roa.self);
        return ERR_SCM_INVALASN;
    }
    if (sta < 0 || (sta = manifestValidate(&roa, &stale)) < 0)
    {
        delete_casn(&roa.self);
        return sta;
    }
    // now, read the data out of the manifest structure
    struct Manifest *manifest =
        &roa.content.signedData.encapContentInfo.eContent.manifest;

    // read the list of files
    uchar file[200];
    struct FileAndHash *fahp;
    manFiles[0] = 0;
    int manFilesLen = 0;
    for (fahp = (struct FileAndHash *)member_casn(&manifest->fileList.self, 0);
         fahp != NULL; fahp = (struct FileAndHash *)next_of(&fahp->self))
    {
        int flth = read_casn(&fahp->file, file);
        file[flth] = 0;
        snprintf(manFiles + manFilesLen, MANFILES_SIZE - manFilesLen,
                 "%s%s", manFilesLen ? " " : "", file);
        if (manFilesLen)
            manFilesLen++;
        manFilesLen += strlen((char *)file);
    }
    int v = 0;
    char ski[60];
    do
    {                           // once through
        // read this_upd and next_upd
        if (vsize_casn(&manifest->thisUpdate) + 1 > (int)sizeof(asn_time))
        {
            LOG(LOG_ERR, "thisUpdate is too large");
            sta = ERR_SCM_INVALDT;
            break;
        }
        sta = read_casn(&manifest->thisUpdate, (unsigned char *)asn_time);
        if (sta < 0)
        {
            LOG(LOG_ERR, "Could not read time for thisUpdate");
            sta = ERR_SCM_INVALDT;
            break;
        }
        else
        {
            asn_time[sta] = '\0';
        }
        thisUpdate = ASNTimeToDBTime(asn_time, &sta, 1);
        if (sta < 0)
            break;

        if (vsize_casn(&manifest->nextUpdate) + 1 > (int)sizeof(asn_time))
        {
            LOG(LOG_ERR, "nextUpdate is too large");
            sta = ERR_SCM_INVALDT;
            break;
        }
        sta = read_casn(&manifest->nextUpdate, (unsigned char *)asn_time);
        if (sta < 0)
        {
            LOG(LOG_ERR, "Could not read time for nextUpdate");
            sta = ERR_SCM_INVALDT;
            break;
        }
        else
        {
            asn_time[sta] = '\0';
        }
        nextUpdate = ASNTimeToDBTime(asn_time, &sta, 1);
        if (sta < 0)
            break;

        if ((sta = extractAndAddCert(&roa, scmp, conp, outdir, utrust, typ,
                                     outfile, ski, certfilename)) < 0)
            break;
        cert_added = 1;
        v = sta;
        if ((sta =
             getmaxidscm(scmp, conp, "local_id", theManifestTable,
                         &man_id)) < 0)
            break;
        man_id++;
    }
    while (0);
    if (sta < 0)
    {
        if (cert_added)
            (void)delete_object(scmp, conp, certfilename, outdir,
                                outfull, (unsigned int)0);
        delete_casn(&roa.self);
        return sta;
    }
    // the manifest is valid if the embedded cert is valid (since we already
    // know that the cert validates the manifest)
    int manValid = (v > 0);

    unsigned int flags = manValid ? SCM_FLAG_VALIDATED : SCM_FLAG_NOCHAIN;
    if (stale)
    {
        flags |= SCM_FLAG_STALEMAN;
    }

    // do the actual insert of the manifest in the db
    scmkva aone;
    scmkv cols[12];
    int idx = 0;
    char did[24],
        mid[24],
        lenbuf[20];
    cols[idx].column = "filename";
    cols[idx++].value = outfile;
    (void)snprintf(did, sizeof(did), "%u", id);
    cols[idx].column = "dir_id";
    cols[idx++].value = did;
    cols[idx].column = "ski";
    cols[idx++].value = ski;
    cols[idx].column = "this_upd";
    cols[idx++].value = thisUpdate;
    cols[idx].column = "next_upd";
    cols[idx++].value = nextUpdate;
    char flagn[24];
    (void)snprintf(flagn, sizeof(flagn), "%u", flags);
    cols[idx].column = "flags";
    cols[idx++].value = flagn;
    (void)snprintf(mid, sizeof(mid), "%u", man_id);
    cols[idx].column = "local_id";
    cols[idx++].value = mid;
    cols[idx].column = "files";
    cols[idx++].value = manFiles;
    cols[idx].column = "fileslen";
    (void)snprintf(lenbuf, sizeof(lenbuf), "%u", manFilesLen);
    cols[idx++].value = lenbuf;
    aone.vec = &cols[0];
    aone.ntot = 12;
    aone.nused = idx;
    aone.vald = 0;
    do
    {
        if ((sta = insertscm(conp, theManifestTable, &aone)) < 0)
            break;

        // if the manifest is valid, update its referenced objects accordingly
        if (manValid && (sta = updateManifestObjs(conp, manifest)) < 0)
            break;
    }
    while (0);
    // clean up
    if (sta < 0 && cert_added)
        (void)delete_object(scmp, conp, certfilename,
                            outdir, outfull, (unsigned int)0);
    delete_casn(&(roa.self));
    free(thisUpdate);
    free(nextUpdate);
    return sta;
}

/*
 * Add the indicated object to the DB. If "trusted" is set then verify that
 * the object is self-signed. Note that this add operation may result in the
 * directory also being added.
 * 
 * Symlinks and files that are not regular files are not processed.
 * 
 * This function returns 0 on success and a negative error code on failure. 
 */

int add_object(
    scm * scmp,
    scmcon * conp,
    char *outfile,
    char *outdir,
    char *outfull,
    int utrust)                 // , char *manState)
{
    unsigned int id = 0,
        obj_id = 0;
    int typ;
    int sta;

    useParacerts = 0;
    if (scmp == NULL || conp == NULL || conp->connected == 0 ||
        outfile == NULL || outdir == NULL || outfull == NULL)
        return (ERR_SCM_INVALARG);
    // make sure it is really a file
    sta = isokfile(outfull);
    if (sta < 0)
        return (sta);
    // determine its filetype
    typ = infer_filetype(outfull);
    if (typ < 0)
        return (typ);
    // find or add the directory
    sta = findorcreatedir(scmp, conp, outdir, &id);
    if (sta < 0)
        return (sta);
    // add the object based on the type
    switch (typ)
    {
    case OT_CER:
    case OT_CER_PEM:
    case OT_UNKNOWN:
    case OT_UNKNOWN + OT_PEM_OFFSET:
        sta = add_cert(scmp, conp, outfile, outfull, id, utrust, typ, &obj_id,
                       0);
        break;
    case OT_CRL:
    case OT_CRL_PEM:
        sta = add_crl(scmp, conp, outfile, outfull, id, utrust, typ);
        break;
    case OT_ROA:
    case OT_ROA_PEM:
        sta = add_roa(scmp, conp, outfile, outdir, outfull, id, utrust, typ);
        break;
    case OT_MAN:
    case OT_MAN_PEM:
        sta =
            add_manifest(scmp, conp, outfile, outdir, outfull, id, utrust,
                         typ);
        break;
    default:
        sta = ERR_SCM_INTERNAL;
        break;
    }
    return (sta);
}

/*
 * This is the internal iteration function used by iterate_crl below. It
 * processes CRLs one at a time.
 * 
 * On failure it returns a negative error code. On success it returns 0. 
 */

static int crliterator(
    scmcon * conp,
    scmsrcha * s,
    int idx)
{
    uint8_t *snlist;
    unsigned int snlen;
    unsigned int sninuse;
    unsigned int flags;
    unsigned int lid;
    unsigned int i;
    crlinfo *crlip;
    char *issuer;
    char *aki;
    int ista;
    int chgd = 0;
    int sta = 0;

    UNREFERENCED_PARAMETER(idx);
    if (conp == NULL || s == NULL || s->context == NULL)
        return (ERR_SCM_INVALARG);
    crlip = (crlinfo *) (s->context);
    if (crlip->conp != conp)
        return (ERR_SCM_INVALARG);
    // if sninuse or snlen is 0 or if the flags mark the CRL as invalid, or
    // if the issuer or aki is a null string, then ignore this CRL
    issuer = (char *)(s->vec[0].valptr);
    if (issuer == NULL || issuer[0] == 0 || s->vec[0].avalsize == 0)
        return (0);
    aki = (char *)(s->vec[6].valptr);
    if (aki == NULL || aki[0] == 0 || s->vec[6].avalsize == 0)
        return (0);
    snlen = *(unsigned int *)(s->vec[1].valptr);
    if (snlen == 0 || s->vec[1].avalsize < (int)(sizeof(unsigned int)))
        return (0);
    sninuse = *(unsigned int *)(s->vec[2].valptr);
    if (sninuse == 0 || s->vec[2].avalsize < (int)(sizeof(unsigned int)))
        return (0);
    flags = *(unsigned int *)(s->vec[3].valptr);
    // ?????????? test for this in where of select statement ???????????????
    if ((flags & SCM_FLAG_VALIDATED) == 0 ||
        (flags & SCM_FLAG_NOCHAIN) != 0 ||
        s->vec[3].avalsize < (int)(sizeof(unsigned int)))
        return (0);
    lid = *(unsigned int *)(s->vec[4].valptr);
    if (s->vec[5].avalsize <= 0)
        return (0);
    snlist = (uint8_t *)(s->vec[5].valptr);
    for (i = 0; i < snlen; i++)
    {
        ista =
            (*crlip->cfunc) (crlip->scmp, crlip->conp, issuer, aki,
                             &snlist[SER_NUM_MAX_SZ * i]);
        if (ista < 0)
            sta = ista;
        if (ista == 1)
        {
            // per STK action item #7 we no longer set SN to zero as an
            // exemplar
            // snlist[i] = 0;
            chgd++;
        }
    }
    // on error do nothing
    if (sta < 0)
        return (sta);
    // no changes: do not update the CRL
    if (chgd == 0)
        return (0);
    // update the sninuse and snlist values
    // per STK action item #7 we are not zero-ing out snlist entries, so
    // we never want to update sninuse
    // sninuse -= chgd;
    if (sninuse > 0)
        sta = updateblobscm(conp, crlip->tabp, snlist, sninuse, snlen, lid);
    else
        sta = deletebylid(conp, crlip->tabp, lid);
    return (sta);
}

/*
 * Iterate through all CRLs in the DB, recursively processing each CRL to
 * obtain its (issuer, snlist) information. For each SN in the list, call a
 * specified function (persumably a certificate revocation function) on that
 * (issuer, sn) combination.
 * 
 * On success this function returns 0.  On failure it returns a negative error 
 * code. 
 */

static uint8_t *snlist = NULL;

int iterate_crl(
    scm * scmp,
    scmcon * conp,
    crlfunc cfunc)
{
    unsigned int snlen = 0;
    unsigned int sninuse = 0;
    unsigned int flags = 0;
    unsigned int lid = 0;
    scmsrcha srch;
    scmsrch srch1[7];
    crlinfo crli;
    char issuer[512];
    char aki[512];
    // void *snlist;
    int sta;

    // go for broke and allocate a blob large enough that it can hold
    // the entire snlist if necessary
    if (snlist == NULL)
        snlist = malloc(16 * 1024 * 1024);
    if (snlist == NULL)
        return (ERR_SCM_NOMEM);
    memset(snlist, 0, 16 * 1024 * 1024);
    initTables(scmp);
    // set up a search for issuer, snlen, sninuse, flags, snlist and aki
    srch1[0].colno = 1;
    srch1[0].sqltype = SQL_C_CHAR;
    srch1[0].colname = "issuer";
    issuer[0] = 0;
    srch1[0].valptr = issuer;
    srch1[0].valsize = 512;
    srch1[0].avalsize = 0;
    srch1[1].colno = 2;
    srch1[1].sqltype = SQL_C_ULONG;
    srch1[1].colname = "snlen";
    srch1[1].valptr = (void *)&snlen;
    srch1[1].valsize = sizeof(unsigned int);
    srch1[1].avalsize = 0;
    srch1[2].colno = 3;
    srch1[2].sqltype = SQL_C_ULONG;
    srch1[2].colname = "sninuse";
    srch1[2].valptr = (void *)&sninuse;
    srch1[2].valsize = sizeof(unsigned int);
    srch1[2].avalsize = 0;
    srch1[3].colno = 4;
    srch1[3].sqltype = SQL_C_ULONG;
    srch1[3].colname = "flags";
    srch1[3].valptr = (void *)&flags;
    srch1[3].valsize = sizeof(unsigned int);
    srch1[3].avalsize = 0;
    srch1[4].colno = 5;
    srch1[4].sqltype = SQL_C_ULONG;
    srch1[4].colname = "local_id";
    srch1[4].valptr = (void *)&lid;
    srch1[4].valsize = sizeof(unsigned int);
    srch1[4].avalsize = 0;
    srch1[5].colno = 6;
    srch1[5].sqltype = SQL_C_BINARY;
    srch1[5].colname = "snlist";
    srch1[5].valptr = snlist;
    srch1[5].valsize = 16 * 1024 * 1024;
    srch1[5].avalsize = 0;
    srch1[6].colno = 7;
    srch1[6].sqltype = SQL_C_CHAR;
    srch1[6].colname = "aki";
    aki[0] = 0;
    srch1[6].valptr = aki;
    srch1[6].valsize = 512;
    srch1[6].avalsize = 0;
    srch.vec = &srch1[0];
    srch.sname = NULL;
    srch.ntot = 7;
    srch.nused = 7;
    srch.vald = 0;
    srch.where = NULL;
    srch.wherestr = NULL;
    crli.scmp = scmp;
    crli.conp = conp;
    crli.tabp = theCRLTable;
    crli.cfunc = cfunc;
    srch.context = (void *)&crli;
    sta = searchscm(conp, theCRLTable, &srch, NULL, crliterator,
                    SCM_SRCH_DOVALUE_ALWAYS, NULL);
    // free(snlist);
    return (sta);
}

/*
 * Fill in the columns for a search with revoke_cert_and_children as callback
 */

static void fillInColumns(
    scmsrch * srch1,
    unsigned int *lid,
    char *ski,
    char *subject,
    unsigned int *flags,
    scmsrcha * srch)
{
    srch1[0].colno = 1;
    srch1[0].sqltype = SQL_C_ULONG;
    srch1[0].colname = "local_id";
    srch1[0].valptr = (void *)lid;
    srch1[0].valsize = sizeof(unsigned int);
    srch1[0].avalsize = 0;
    srch1[1].colno = 2;
    srch1[1].sqltype = SQL_C_CHAR;
    srch1[1].colname = "ski";
    srch1[1].valptr = (void *)ski;
    srch1[1].valsize = 512;
    srch1[1].avalsize = 0;
    srch1[2].colno = 3;
    srch1[2].sqltype = SQL_C_CHAR;
    srch1[2].colname = "subject";
    srch1[2].valptr = (void *)subject;
    srch1[2].valsize = 512;
    srch1[2].avalsize = 0;
    srch1[3].colno = 4;
    srch1[3].sqltype = SQL_C_ULONG;
    srch1[3].colname = "flags";
    srch1[3].valptr = (void *)flags;
    srch1[3].valsize = sizeof(unsigned int);
    srch1[3].avalsize = 0;
    srch->vec = srch1;
    srch->sname = NULL;
    srch->ntot = 4;
    srch->nused = 4;
    srch->vald = 0;
}

/*
 * This is the model revocation function for certificates. It handles the case 
 * where a certificate is expired or revoked. Given that this function can be
 * called recursively it must be careful in what it does. If the top level
 * certificate it is handed has either the EXPIRED or REVOKED bit set in its
 * flags field, or the toplevel flag in the search context, then it is
 * deleted. If none of these bits it set then it checks to see if it has been
 * reparented. If it has not been reparented, it is deleted, otherwise the
 * function just returns.
 * 
 * If a certificate is deleted, then this function is invoked recursively to
 * check to see if any of its children (certificate children or ROA children)
 * also need to be deleted. 
 */

static int revoke_cert_and_children(
    scmcon * conp,
    scmsrcha * s,
    int idx)
{
    unsigned int lid;
    int sta;

    UNREFERENCED_PARAMETER(idx);
    lid = *(unsigned int *)(s->vec[0].valptr);
    if ((sta = deletebylid(conp, theCertTable, lid)) < 0)
        return sta;
    char *ski = (char *)(s->vec[1].valptr);
    ulong flags = *(unsigned int *)(s->vec[3].valptr);
    if ((flags & SCM_FLAG_ISPARACERT))
    {                           // is its regular cert in the DB with unneeded 
                                // flags?
        struct cert_answers *cert_answersp;
        struct cert_ansr *cert_ansrp;
        cert_answersp = find_cert_by_aKI(ski, (char *)0, theSCMP, conp);
        if (cert_answersp && cert_answersp->num_ansrs)
        {
            int i;
            for (i = 0, cert_ansrp = &cert_answersp->cert_ansrp[i];
                 i < cert_answersp->num_ansrs; i++, cert_ansrp++)
            {
                if ((cert_ansrp->
                     flags & (SCM_FLAG_HASPARACERT || SCM_FLAG_ISTARGET)))
                {               // if so, clear them
                    flags = (cert_ansrp->flags &
                             ~(SCM_FLAG_HASPARACERT | SCM_FLAG_ISTARGET));
                    set_cert_flag(conp, cert_ansrp->local_id, flags);
                }
            }
        }
    }
    if (sta < 0)
        return sta;
    return verifyOrNotChildren(conp, (char *)s->vec[1].valptr,
                               (char *)s->vec[2].valptr, NULL, NULL, lid, 0);
}

/*
 * Delete an object. First find the object's directory. If it is not found
 * then we are done. If it is found, then find the corresponding (filename,
 * dir_id) combination in the appropriate table and issue the delete SQL call. 
 */

int delete_object(
    scm * scmp,
    scmcon * conp,
    char *outfile,
    char *outdir,
    char *outfull,
    unsigned int dir_id)
{
    unsigned int id;
    unsigned int blah;
    unsigned int lid;
    unsigned int flags;
    scmsrcha srch;
    scmsrch srch1,
        srch2[5];
    scmkva where;
    scmkva dwhere;
    scmkv one;
    scmkv dtwo[2];
    scmtab *thetab;
    int typ;
    int sta;
    char ski[512];
    char subject[512];
    char did[24];
    mcf mymcf;

    if (conp == NULL || conp->connected == 0 || outfile == NULL ||
        (outdir == NULL && !dir_id))
        return (ERR_SCM_INVALARG);
    // determine its filetype
    typ = infer_filetype(outfile);
    if (typ < 0)
        return (typ);
    // find the directory
    if (scmp)
        initTables(scmp);       // may be null if tables have been initiated
    if (outdir)
    {
        one.column = "dirname";
        one.value = outdir;
        where.vec = &one;
        where.ntot = 1;
        where.nused = 1;
        where.vald = 0;
        srch1.colno = 1;
        srch1.sqltype = SQL_C_ULONG;
        srch1.colname = "dir_id";
        srch1.valptr = (void *)&id;
        srch1.valsize = sizeof(unsigned int);
        srch1.avalsize = 0;
        srch.vec = &srch1;
        srch.sname = NULL;
        srch.ntot = 1;
        srch.nused = 1;
        srch.vald = 0;
        srch.where = &where;
        srch.wherestr = NULL;
        srch.context = &blah;
        sta =
            searchscm(conp, theDirTable, &srch, NULL, ok,
                      SCM_SRCH_DOVALUE_ALWAYS, NULL);
        if (sta < 0)
            return (sta);
    }
    else
        id = dir_id;
    // fill in where structure
    dtwo[0].column = "filename";
    dtwo[0].value = outfile;
    dtwo[1].column = "dir_id";
    (void)snprintf(did, sizeof(did), "%u", id);
    dtwo[1].value = did;
    dwhere.vec = &dtwo[0];
    dwhere.ntot = 2;
    dwhere.nused = 2;
    dwhere.vald = 0;
    // delete the object based on the type
    // note that the directory itself is not deleted
    thetab = NULL;
    switch (typ)
    {
    case OT_CER:
    case OT_CER_PEM:
    case OT_UNKNOWN:
    case OT_UNKNOWN + OT_PEM_OFFSET:
        thetab = theCertTable;
        mymcf.did = 0;
        mymcf.toplevel = 1;
        fillInColumns(srch2, &lid, ski, subject, &flags, &srch);
        srch.where = &dwhere;
        srch.context = &mymcf;
        sta = searchscm(conp, thetab, &srch, NULL, revoke_cert_and_children,
                        SCM_SRCH_DOVALUE_ALWAYS, NULL);
        break;
    case OT_CRL:
    case OT_CRL_PEM:
        thetab = theCRLTable;
        break;
    case OT_ROA:
    case OT_ROA_PEM:
        thetab = theROATable;
        break;
    case OT_MAN:
    case OT_MAN_PEM:
        thetab = theManifestTable;
        break;
    default:
        sta = ERR_SCM_INTERNAL;
        break;
    }
    if (thetab == NULL)
        sta = ERR_SCM_NOSUCHTAB;
    if (sta < 0)
        return (sta);
    sta = deletescm(conp, thetab, &dwhere);
    if (sta != 0)
        return sta;
    if (typ == OT_ROA || typ == OT_ROA_PEM || typ == OT_MAN
        || typ == OT_MAN_PEM)
    {
        unsigned int ndir_id;
        char noutfile[PATH_MAX],
            noutdir[PATH_MAX],
            noutfull[PATH_MAX];
        memset(noutfile, 0, PATH_MAX);
        memset(noutdir, 0, PATH_MAX);
        memset(noutfull, 0, PATH_MAX);
        char *c = retrieve_tdir(scmp, conp, &sta);
        int lth = strlen(c);    // lth of tdir
        strcat(strcpy(noutfull, c), "/EEcertificates");
        free((void *)c);
        c = NULL;
        findorcreatedir(scmp, conp, noutfull, &ndir_id);
        strcpy(noutdir, noutfull);
        strcat(noutdir, &outdir[lth]);
        strcat(noutfull, &outfull[lth]);        // add roa path + name
        strcat(noutfull, ".cer");
        strcat(strcpy(noutfile, outfile), ".cer");


        if ((sta = delete_object(scmp, conp, noutfile, noutdir,
                                 noutfull, ndir_id)) < 0)
            return sta;
    }
    return (sta);
}

/*
 * This is the model callback function for iterate_crl. For each (issuer, sn)
 * pair with sn != 0 it attempts to find a certificate with those values in
 * the DB. If found, it then attempts to delete the certificate and all its
 * children. Note that in deleting an EE certificate, some of its children may 
 * be ROAs, so this table has to be searched as well.
 * 
 * This function returns 1 if it deleted something, 0 if it deleted nothing
 * and a negative error code on failure. 
 */

int model_cfunc(
    scm * scmp,
    scmcon * conp,
    char *issuer,
    char *aki,
    uint8_t *sn)
{
    unsigned int lid;
    unsigned int flags;
    scmsrcha srch;
    scmsrch srch1[5];
    scmkva where;
    scmkv w[3];
    mcf mymcf;
    char ski[512];
    char subject[512];
    char *sno;
    uint8_t sn_zero[SER_NUM_MAX_SZ];
    int sta;

    memset(sn_zero, 0, sizeof(sn_zero));

    if (scmp == NULL || conp == NULL || conp->connected == 0)
        return (ERR_SCM_INVALARG);
    if (issuer == NULL || issuer[0] == 0 || aki == NULL || aki[0] == 0 ||
        memcmp(sn, sn_zero, SER_NUM_MAX_SZ) == 0)
        return (0);
    initTables(scmp);
    mymcf.did = 0;
    mymcf.toplevel = 1;
    w[0].column = "issuer";
    w[0].value = issuer;
    sno = hexify(SER_NUM_MAX_SZ, sn, HEXIFY_HAT);
    if (sno == NULL)
    {
        return (ERR_SCM_NOMEM);
    }
    w[1].column = "sn";
    w[1].value = &sno[0];
    w[2].column = "aki";
    w[2].value = aki;
    where.vec = &w[0];
    where.ntot = 3;
    where.nused = 3;
    where.vald = 0;
    fillInColumns(srch1, &lid, ski, subject, &flags, &srch);
    srch.where = &where;
    srch.wherestr = NULL;
    srch.context = &mymcf;
    sta = searchscm(conp, theCertTable, &srch, NULL, revoke_cert_and_children,
                    SCM_SRCH_DOVALUE_ALWAYS, NULL);
    free(sno);
    sno = NULL;
    if (sta < 0)
        return (sta);
    else
        return (mymcf.did == 0 ? 0 : 1);
}

/*
 * Delete a particular local_id from a table. 
 */

int deletebylid(
    scmcon * conp,
    scmtab * tabp,
    unsigned int lid)
{
    scmkva lids;
    scmkv where;
    char mylid[24];
    int sta;

    if (conp == NULL || conp->connected == 0 || tabp == NULL)
        return (ERR_SCM_INVALARG);
    where.column = "local_id";
    (void)snprintf(mylid, sizeof(mylid), "%u", lid);
    where.value = mylid;
    lids.vec = &where;
    lids.ntot = 1;
    lids.nused = 1;
    lids.vald = 0;
    sta = deletescm(conp, tabp, &lids);
    return (sta);
}

/*
 * This is the callback for certificates that are may have been NOTYET but are 
 * now actually valid. Mark them as such. 
 */

static int certmaybeok(
    scmcon * conp,
    scmsrcha * s,
    int idx)
{
    unsigned int pflags;
    scmkva where;
    scmkv one;
    char lid[24];
    int sta;

    UNREFERENCED_PARAMETER(idx);
    pflags = *(unsigned int *)(s->vec[3].valptr);
    // ????????? instead test for this in select statement ????????
    if ((pflags & SCM_FLAG_NOTYET) == 0)
        return (0);
    (void)snprintf(lid, sizeof(lid), "%u",
                   *(unsigned int *)(s->vec[0].valptr));
    one.column = "local_id";
    one.value = &lid[0];
    where.vec = &one;
    where.ntot = 1;
    where.nused = 1;
    where.vald = 0;
    pflags &= ~SCM_FLAG_NOTYET;
    sta = setflagsscm(conp, theCertTable, &where, pflags);
    return (sta);
}

/*
 * This is the callback for certificates that are too new, e.g. not yet valid. 
 * Mark them as NOTYET in the flags field. 
 */

static int certtoonew(
    scmcon * conp,
    scmsrcha * s,
    int idx)
{
    unsigned int pflags;
    scmkva where;
    scmkv one;
    char lid[24];
    int sta;

    UNREFERENCED_PARAMETER(idx);
    (void)snprintf(lid, sizeof(lid), "%u",
                   *(unsigned int *)(s->vec[0].valptr));
    one.column = "local_id";
    one.value = &lid[0];
    where.vec = &one;
    where.ntot = 1;
    where.nused = 1;
    where.vald = 0;
    pflags = *(unsigned int *)(s->vec[3].valptr);
    pflags |= SCM_FLAG_NOTYET;
    sta = setflagsscm(conp, theCertTable, &where, pflags);
    return (sta);
}

/*
 * This is the callback for certificates that are too old, e.g. no longer
 * valid. Delete them (and their children) unless they have been reparented. 
 */

static int certtooold(
    scmcon * conp,
    scmsrcha * s,
    int idx)
{
    char *ws;
    int tl;
    int sta;
    mcf *mymcf;

    ws = s->wherestr;
    s->wherestr = NULL;
    mymcf = (mcf *) (s->context);
    tl = mymcf->toplevel;
    mymcf->toplevel = 1;
    sta = revoke_cert_and_children(conp, s, idx);
    s->wherestr = ws;
    mymcf->toplevel = tl;
    return (sta);
}

/*
 * This function sweeps through all certificates. If it finds any that are
 * valid but marked as NOTYET, it clears the NOTYET bit and sets the VALID
 * bit. If it finds any where the start validity date (valfrom) is in the
 * future, it marks them as NOTYET. If it finds any where the end validity
 * date (valto) is in the past, it deletes them. 
 */

int certificate_validity(
    scm * scmp,
    scmcon * conp)
{
    unsigned int lid,
        flags;
    scmsrcha srch;
    scmsrch srch1[5];
    mcf mymcf;
    char skistr[512];
    char subjstr[512];
    char *vok;
    char *vf;
    char *vt;
    char *now;
    int retsta = 0;
    int sta = 0;

    if (scmp == NULL || conp == NULL || conp->connected == 0)
        return (ERR_SCM_INVALARG);
    initTables(scmp);
    now = LocalTimeToDBTime(&sta);
    if (now == NULL)
        return (sta);
    // construct the validity clauses
    vok = (char *)calloc(48 + 2 * strlen(now), sizeof(char));
    if (vok == NULL)
        return (ERR_SCM_NOMEM);
    (void)snprintf(vok, 48 + 2 * strlen(now),
                   "valfrom <= \"%s\" AND \"%s\" <= valto", now, now);
    vf = (char *)calloc(24 + strlen(now), sizeof(char));
    if (vf == NULL)
        return (ERR_SCM_NOMEM);
    (void)snprintf(vf, 24 + strlen(now), "\"%s\" < valfrom", now);
    vt = (char *)calloc(24 + strlen(now), sizeof(char));
    if (vt == NULL)
        return (ERR_SCM_NOMEM);
    (void)snprintf(vt, 24 + strlen(now), "valto < \"%s\"", now);
    free((void *)now);
    // search for certificates that might now be valid
    // in order to use revoke_cert_and_children the first five
    // columns of the search must be the lid, ski, flags, issuer and aki
    fillInColumns(srch1, &lid, skistr, subjstr, &flags, &srch);
    srch.where = NULL;
    srch.wherestr = vok;
    mymcf.did = 0;
    mymcf.toplevel = 0;
    srch.context = (void *)&mymcf;
    sta = searchscm(conp, theCertTable, &srch, NULL,
                    certmaybeok, SCM_SRCH_DOVALUE_ALWAYS, NULL);
    free((void *)vok);
    if (sta < 0 && sta != ERR_SCM_NODATA)
        retsta = sta;
    // search for certificates that are too new
    srch.wherestr = vf;
    // ?????????????? no need to call this here; instead ??????????
    // ?????????????? check when first put in ????????????
    sta = searchscm(conp, theCertTable, &srch, NULL,
                    certtoonew, SCM_SRCH_DOVALUE_ALWAYS, NULL);
    free((void *)vf);
    if (sta < 0 && sta != ERR_SCM_NODATA && retsta == 0)
        retsta = sta;
    // search for certificates that are too old
    srch.wherestr = vt;
    sta = searchscm(conp, theCertTable, &srch, NULL,
                    certtooold, SCM_SRCH_DOVALUE_ALWAYS, NULL);
    free((void *)vt);
    if (sta < 0 && sta != ERR_SCM_NODATA && retsta == 0)
        retsta = sta;
    return (retsta);
}

/*
 * Update the metadata table to indicate when a particular client ran last. 
 */

int ranlast(
    scm * scmp,
    scmcon * conp,
    char *whichcli)
{
    char *now;
    char what;
    int sta = 0;

    if (scmp == NULL || conp == NULL || conp->connected == 0 ||
        whichcli == NULL || whichcli[0] == 0)
        return (ERR_SCM_INVALARG);
    what = toupper((int)(whichcli[0]));
    if (what != 'R' && what != 'Q' && what != 'C' && what != 'G')
        return (ERR_SCM_INVALARG);
    initTables(scmp);
    conp->mystat.tabname = "METADATA";
    now = LocalTimeToDBTime(&sta);
    if (now == NULL)
        return (sta);
    sta = updateranlastscm(conp, theMetaTable, what, now);
    free((void *)now);
    return (sta);
}

/*
 * Given the SKI of a ROA, this function returns the X509 * structure for the
 * corresponding EE certificate (or NULL on error). 
 */

void *roa_parent(
    scm * scmp,
    scmcon * conp,
    char *ski,
    char **fn,
    int *stap)
{
    initTables(scmp);
    return parent_cert(conp, ski, NULL, stap, fn, NULL);
}

/*
 * open syslog and write message that application started
 */

static char *logName = NULL;

void startSyslog(
    char *appName)
{
    // static char *logName = 0; /* need to save this for syslog's reuse */
    if (logName != NULL)
    {
        free(logName);
        logName = NULL;
    }                           /* previous logName */
    logName = (char *)calloc(6 + strlen(appName), sizeof(char));
    snprintf(logName, 6 + strlen(appName), "RPKI %s", appName);
    openlog(logName, LOG_PID, 0);
    syslog(LOG_NOTICE, "Application Started");
}

/*
 * close syslog and write message that application ended
 */

void stopSyslog(
    void)
{
    syslog(LOG_NOTICE, "Application Ended");
    closelog();
    if (logName != NULL)
    {
        free(logName);
        logName = NULL;
    }
}

/*
 * Free all memory held in global variables 
 */

void sqcleanup(
    void)
{
    if (parentSrch != NULL)
    {
        freesrchscm(parentSrch);
        parentSrch = NULL;
    }
    if (revokedSrch != NULL)
    {
        freesrchscm(revokedSrch);
        revokedSrch = NULL;
    }
    if (updateManSrch != NULL)
    {
        freesrchscm(updateManSrch);
        updateManSrch = NULL;
    }
    if (updateManSrch2 != NULL)
    {
        freesrchscm(updateManSrch2);
        updateManSrch2 = NULL;
    }
    if (crlSrch != NULL)
    {
        freesrchscm(crlSrch);
        crlSrch = NULL;
    }
    if (manSrch != NULL)
    {
        freesrchscm(manSrch);
        manSrch = NULL;
    }
    if (roaSrch != NULL)
    {
        freesrchscm(roaSrch);
        roaSrch = NULL;
    }
    if (childrenSrch != NULL)
    {
        freesrchscm(childrenSrch);
        childrenSrch = NULL;
    }
    if (validManSrch != NULL)
    {
        freesrchscm(validManSrch);
        validManSrch = NULL;
    }
    if (snlist != NULL)
    {
        free(snlist);
        snlist = NULL;
    }

    if (iPropData.data)
        free(iPropData.data);
    if (vPropData.data)
        free(vPropData.data);
}
