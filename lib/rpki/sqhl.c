#include "sqhl.h"

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
#include "diru.h"
#include "myssl.h"
#include "err.h"
#include "rpwork.h"
#include "casn/casn.h"
#include "rpki-asn1/crlv2.h"

#include "cms/roa_utils.h"
#include "util/logging.h"
#include "util/macros.h"
#include "util/stringutils.h"


#define ADDCOL(a, b, c, d, e, f)                                        \
    ADDCOL2((a), (b), (c), (d), (e), return (f))

#define ADDCOL2(a, b, c, d, e, f)                                       \
    do {                                                                \
        e = addcolsrchscm((a), (b), (c), (d));                          \
        if ((e) < 0)                                                    \
        {                                                               \
            f;                                                          \
        }                                                               \
    } while (0)

/*
 * static variables that hold tables and function to initialize them
 */

static scmtab *theCertTable = NULL;
static scmtab *theROATable = NULL;
static scmtab *theROAPrefixTable = NULL;
static scmtab *theCRLTable = NULL;
static scmtab *theManifestTable = NULL;
static scmtab *theGBRTable = NULL;
static scmtab *theDirTable = NULL;
static scmtab *theMetaTable = NULL;
static scm *theSCMP = NULL;
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
        theROAPrefixTable = findtablescm(scmp, "ROA_PREFIX");
        if (theROAPrefixTable == NULL)
        {
            LOG(LOG_ERR, "Error finding roa_prefix table");
            exit(-1);
        }
        theManifestTable = findtablescm(scmp, "MANIFEST");
        if (theManifestTable == NULL)
        {
            LOG(LOG_ERR, "Error finding manifest table");
            exit(-1);
        }
        theGBRTable = findtablescm(scmp, "GHOSTBUSTERS");
        if (theGBRTable == NULL)
        {
            LOG(LOG_ERR, "Error finding ghostbusters table");
            exit(-1);
        }
        theSCMP = scmp;
    }
}

err_code
findorcreatedir(
    scm *scmp,
    scmcon *conp,
    const char *dirname,
    unsigned int *idp)
{
    scmsrcha *srch;
    err_code sta;

    if (conp == NULL || conp->connected == 0 || dirname == NULL ||
        dirname[0] == 0 || idp == NULL)
        return (ERR_SCM_INVALARG);
    *idp = (unsigned int)(-1);
    conp->mystat.tabname = "DIRECTORY";
    initTables(scmp);
    scmkv two[] = {
        {"dir_id", NULL},
        {"dirname", dirname},
    };
    scmkva where = {
        .vec = &two[1],
        .ntot = 1,
        .nused = 1,
        .vald = 0,
    };
    scmkva ins = {
        .vec = two,
        .ntot = ELTS(two),
        .nused = ELTS(two),
        .vald = 0,
    };
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

static sqlvaluefunc ok;
err_code
ok(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    UNREFERENCED_PARAMETER(conp);
    UNREFERENCED_PARAMETER(s);
    UNREFERENCED_PARAMETER(idx);
    return (0);
}

/**
 * @brief
 *     Ask the DB about the top level repos directory.
 *
 * If found return a copy of the dirname. On error return NULL and set
 * stap.
 */
char *retrieve_tdir(
    scm *scmp,
    scmcon *conp,
    err_code *stap)
{
    char *oot;
    err_code sta;

    if (scmp == NULL || conp == NULL || conp->connected == 0 || stap == NULL)
        /** @bug *stap is not set if stap is non-NULL */
        return (NULL);
    conp->mystat.tabname = "METADATA";
    initTables(scmp);
    scmkv one[] = {
        {"local_id", "1"},
    };
    scmkva where = {
        .vec = one,
        .ntot = ELTS(one),
        .nused = ELTS(one),
        .vald = 0,
    };
    oot = calloc(PATH_MAX, sizeof(char));
    if (oot == NULL)
    {
        *stap = ERR_SCM_NOMEM;
        return (NULL);
    }
    scmsrch srch1[] = {
        {
            .colno = 1,
            .sqltype = SQL_C_CHAR,
            .colname = "rootdir",
            .valptr = oot,
            .valsize = PATH_MAX,
            .avalsize = 0,
        },
    };
    scmsrcha srch = {
        .vec = srch1,
        .sname = NULL,
        .ntot = ELTS(srch1),
        .nused = ELTS(srch1),
        .vald = 0,
        .where = &where,
        .wherestr = NULL,
    };
    sta = searchscm(conp, theMetaTable, &srch, NULL,
                    &ok, SCM_SRCH_DOVALUE_ALWAYS, NULL);
    if (sta < 0)
    {
        free(oot);
        oot = NULL;
    }
    *stap = sta;
    return (oot);
}

/*
 * Ask the DB if it has any matching signatures to the one passed in. This
 * function works on any of the three tables that have signatures.
 */

static err_code
dupsigscm(
    scm *scmp,
    scmcon *conp,
    scmtab *tabp,
    char *msig)
{
    unsigned long lid;
    err_code sta;

    if (scmp == NULL || conp == NULL || conp->connected == 0 ||
        tabp == NULL || msig == NULL || msig[0] == 0)
        return (ERR_SCM_INVALARG);
    conp->mystat.tabname = tabp->hname;
    initTables(scmp);
    scmkv one[] = {
        {"sig", msig},
    };
    scmkva where = {
        .vec = one,
        .ntot = ELTS(one),
        .nused = ELTS(one),
        .vald = 0,
    };
    scmsrch srch1[] = {
        {
            .colno = 1,
            .sqltype = SQL_C_LONG,
            .colname = "local_id",
            .valptr = &lid,
            .valsize = sizeof(lid),
            .avalsize = 0,
        },
    };
    scmsrcha srch = {
        .vec = srch1,
        .sname = NULL,
        .ntot = ELTS(srch1),
        .nused = ELTS(srch1),
        .vald = 0,
        .where = &where,
        .wherestr = NULL,
    };
    sta = searchscm(conp, tabp, &srch, NULL,
                    &ok, SCM_SRCH_DOVALUE_ALWAYS, NULL);
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

/**
 * @brief
 *     test whether a string has a particular suffix
 */
static _Bool
ends_with(
    const char *str,
    size_t lenstr,
    const char *sfx,
    size_t lensfx)
{
    assert(str);
    assert(sfx);
    if (lensfx > lenstr)
        return 0;
    return (0 == strncmp(str + lenstr - lensfx, sfx, lensfx));
}

object_type
infer_filetype(
    const char *fname)
{
    struct {
        const char *const sfx;
        const size_t lensfx;
        const object_type typ;
    } *rulep, rules[] = {
        {".cer", 4, OT_CER},
        {".crl", 4, OT_CRL},
        {".roa", 4, OT_ROA},
        {".man", 4, OT_MAN},
        {".mft", 4, OT_MAN},
        {".mnf", 4, OT_MAN},
        {".gbr", 4, OT_GBR},
        {".cer.pem", 8, OT_CER_PEM},
        {".crl.pem", 8, OT_CRL_PEM},
        {".roa.pem", 8, OT_ROA_PEM},
        {".man.pem", 8, OT_MAN_PEM},
        {".mft.pem", 8, OT_MAN_PEM},
        {".mnf.pem", 8, OT_MAN_PEM},
        {NULL, 0, OT_UNKNOWN} // must be last
    };

    assert(fname);

    size_t lenfname = strlen(fname);

    for (rulep = &rules[0]; rulep->sfx; ++rulep)
    {
        if (ends_with(fname, lenfname, rulep->sfx, rulep->lensfx))
            return rulep->typ;
    }
    // return the type in the NULL rule
    return rulep->typ;
}

// so that manifest can get id of previous cert

static unsigned int lastCertIDAdded = 0;

static char *certf[CF_NFIELDS] = {
    "filename", "subject", "issuer", "sn", "valfrom", "valto", "sig",
    "ski", "aki", "sia", "aia", "crldp"
};

static err_code
add_cert_internal(
    scm *scmp,
    scmcon *conp,
    cert_fields *cf,
    unsigned int *cert_id)
{
    scmkv cols[CF_NFIELDS + 5];
    char *wptr = NULL;
    char *ptr;
    char flagn[24];
    char lid[24];
    char did[24];
    char blen[24];
    int idx = 0;
    err_code sta;
    int i;
    char *escaped_strings[CF_NFIELDS] = {NULL};

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
    for (i = 0; (size_t)i < ELTS(cols); i++)
        cols[i].value = NULL;
    for (i = 0; i < CF_NFIELDS; i++)
    {
        if ((ptr = cf->fields[i]) != NULL)
        {
            escaped_strings[i] = malloc(strlen(ptr)*2+1);
            if(escaped_strings[i] == NULL) {
                sta = ERR_SCM_NOMEM;
                goto cleanup;
            }
            mysql_escape_string(escaped_strings[i], ptr, strlen(ptr));
            cols[idx++] = (scmkv){certf[i], escaped_strings[i]};
        }
    }
    xsnprintf(flagn, sizeof(flagn), "%u", cf->flags);
    cols[idx++] = (scmkv){"flags", flagn};
    xsnprintf(lid, sizeof(lid), "%u", *cert_id);
    cols[idx++] = (scmkv){"local_id", lid};
    xsnprintf(did, sizeof(did), "%u", cf->dirid);
    cols[idx++] = (scmkv){"dir_id", did};
    if (cf->ipblen > 0)
    {
        xsnprintf(blen, sizeof(blen), "%u", cf->ipblen);   /* byte length */
        cols[idx++] = (scmkv){"ipblen", blen};
        wptr = hexify(cf->ipblen, cf->ipb, HEXIFY_HAT);
        if (wptr == NULL)
            return (ERR_SCM_NOMEM);
        cols[idx++] = (scmkv){"ipb", wptr};
    }
    scmkva aone = {
        .vec = cols,
        .ntot = ELTS(cols),
        .nused = idx,
        .vald = 0,
    };
    sta = insertscm(conp, theCertTable, &aone);
cleanup:
    for (i = 0; i < CF_NFIELDS; i++)
    {
        free(escaped_strings[i]);
    }
    if (wptr != NULL)
    {
        free(wptr);
    }
    lastCertIDAdded = *cert_id;
    return (sta);
}

static char *crlf[CRF_NFIELDS] = {
    "filename", "issuer", "last_upd", "next_upd", "sig", "crlno", "aki"
};

static err_code
add_crl_internal(
    scm *scmp,
    scmcon *conp,
    crl_fields *cf)
{
    unsigned int crl_id = 0;
    scmkv cols[CRF_NFIELDS + 6];
    char *ptr;
    char *hexs;
    char flagn[24];
    char lid[24] = {'\0'};
    char did[24];
    char csnlen[24];
    int idx = 0;
    err_code sta;
    int i;
    char *escaped_strings[CRF_NFIELDS] = {NULL};

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
    for (i = 0; (size_t)i < ELTS(cols); i++)
        cols[i].value = NULL;
    for (i = 0; i < CRF_NFIELDS; i++)
    {
        if ((ptr = cf->fields[i]) != NULL)
        {
            escaped_strings[i] = malloc(strlen(ptr)*2+1);
            if(escaped_strings[i] == NULL) {
                sta = ERR_SCM_NOMEM;
                goto cleanup;
            }
            mysql_escape_string(escaped_strings[i], ptr, strlen(ptr));
            cols[idx++] = (scmkv){crlf[i], escaped_strings[i]};
        }
    }
    xsnprintf(flagn, sizeof(flagn), "%u", cf->flags);
    cols[idx++] = (scmkv){"flags", flagn};
    xsnprintf(lid, sizeof(lid), "%u", crl_id);
    cols[idx++] = (scmkv){"local_id", lid};
    xsnprintf(did, sizeof(did), "%u", cf->dirid);
    cols[idx++] = (scmkv){"dir_id", did};
    xsnprintf(csnlen, sizeof(csnlen), "%d", cf->snlen);
    cols[idx++] = (scmkv){"snlen", csnlen};
    cols[idx++] = (scmkv){"sninuse", csnlen};
    cols[idx++] = (scmkv){"snlist", hexs};
    scmkva aone = {
        .vec = cols,
        .ntot = ELTS(cols),
        .nused = idx,
        .vald = 0,
    };
    // add the CRL
    sta = insertscm(conp, theCRLTable, &aone);
cleanup:
    free(hexs);
    for (i = 0; i < CRF_NFIELDS; i++)
    {
        free(escaped_strings[i]);
    }
    return (sta);
}

/*
 * Callback function used in verification.
 */

static int verify_callback(
    int ok2,
    X509_STORE_CTX *store)
{
    if (!ok2)
        LOG(LOG_ERR, "Error: %s",
            X509_verify_cert_error_string(store->error));
    return (ok2);
}

/**
 * @brief
 *     This function gets the sigval parameter from a table based on
 *     the type.
 *
 * @return
 *     One of the SIGVAL_ constants indicating what happened.
 */
static sigval_state
get_cert_sigval(
    scmcon *conp,
    char *subj,
    char *ski)
{
    static scmsrcha *sigsrch = NULL;
    unsigned int *svalp;
    sigval_state sval;
    err_code sta = 0;

    if (theSCMP != NULL)
        initTables(theSCMP);
    if (sigsrch == NULL)
    {
        /** @bug ignores error code (NULL) without explanation */
        sigsrch = newsrchscm(NULL, 1, 0, 1);
        /**
         * @bug on error sigsrch will be left in a half-initialized
         * state and it will never be fully initialized
         */
        ADDCOL(sigsrch, "sigval", SQL_C_ULONG, sizeof(unsigned int), sta,
               SIGVAL_UNKNOWN);
    }
    xsnprintf(sigsrch->wherestr, WHERESTR_SIZE,
              "ski=\"%s\" and subject=\"%s\"", ski, subj);
    sta = searchscm(conp, theCertTable, sigsrch, NULL, &ok,
                    SCM_SRCH_DOVALUE_ALWAYS, NULL);
    if (sta < 0)
        return SIGVAL_UNKNOWN;
    svalp = (unsigned int *)(sigsrch->vec[0].valptr);
    if (svalp == NULL)
        return SIGVAL_UNKNOWN;
    sval = *svalp;
    if (sval < SIGVAL_UNKNOWN || sval > SIGVAL_INVALID)
        return SIGVAL_UNKNOWN;
    return sval;
}

static sigval_state
get_roa_sigval(
    scmcon *conp,
    char *ski)
{
    static scmsrcha *sigsrch = NULL;
    unsigned int *svalp;
    sigval_state sval;
    err_code sta = 0;

    if (theSCMP != NULL)
        initTables(theSCMP);
    if (sigsrch == NULL)
    {
        /** @bug ignores error code (NULL) without explanation */
        sigsrch = newsrchscm(NULL, 1, 0, 1);
        /**
         * @bug on error sigsrch will be left in a half-initialized
         * state and it will never be fully initialized
         */
        ADDCOL(sigsrch, "sigval", SQL_C_ULONG, sizeof(unsigned int), sta,
               SIGVAL_UNKNOWN);
    }
    xsnprintf(sigsrch->wherestr, WHERESTR_SIZE, "ski=\"%s\"", ski);
    sta = searchscm(conp, theROATable, sigsrch, NULL, &ok,
                    SCM_SRCH_DOVALUE_ALWAYS, NULL);
    if (sta < 0)
        return SIGVAL_UNKNOWN;
    svalp = (unsigned int *)(sigsrch->vec[0].valptr);
    if (svalp == NULL)
        return SIGVAL_UNKNOWN;
    sval = *svalp;
    if (sval < SIGVAL_UNKNOWN || sval > SIGVAL_INVALID)
        return SIGVAL_UNKNOWN;
    return sval;
}

static sigval_state
get_sigval(
    scmcon *conp,
    object_type typ,
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

/**
 * @brief
 *     This function attempts to set the sigval parameter in a table
 *     based on the type.
 */
static err_code
set_cert_sigval(
    scmcon *conp,
    char *subj,
    char *ski,
    sigval_state valu)
{
    char stmt[520];
    err_code sta;

    if (theSCMP != NULL)
        initTables(theSCMP);
    if (theCertTable == NULL)
        return ERR_SCM_NOSUCHTAB;
    char escaped_subj[2 * strlen(subj) + 1];
    mysql_escape_string(escaped_subj, subj, strlen(subj));
    xsnprintf(stmt, sizeof(stmt),
              "update %s set sigval=%d where ski=\"%s\" and subject=\"%s\";",
              theCertTable->tabname, valu, ski, escaped_subj);
    sta = statementscm_no_data(conp, stmt);
    return sta;
}

static err_code
set_roa_sigval(
    scmcon *conp,
    char *ski,
    sigval_state valu)
{
    char stmt[520];
    err_code sta;

    if (theSCMP != NULL)
        initTables(theSCMP);
    if (theROATable == NULL)
        return ERR_SCM_NOSUCHTAB;
    xsnprintf(stmt, sizeof(stmt),
              "update %s set sigval=%d where ski=\"%s\";",
              theROATable->tabname, valu, ski);
    sta = statementscm_no_data(conp, stmt);
    return sta;
}

static err_code
set_sigval(
    scmcon *conp,
    object_type typ,
    char *item1,
    char *item2,
    sigval_state valu)
{
    err_code sta = ERR_SCM_UNSPECIFIED;

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

typedef int
vfunc(
    X509_STORE_CTX *);

/*
 * Global variables used by the verification callback
 */

static vfunc *old_vfunc = NULL;
static scmcon *thecon = NULL;

/*
 * Our replacement for X509_verify. Consults the database first to see if the
 * certificate is already valid, otherwise calls X509_verify and then sets the
 * state in the db based on that. It returns 1 on success and 0 on failure.
 */

static int local_verify(
    X509 *cert,
    EVP_PKEY *pkey)
{
    int x509sta = 0;
    err_code sta = 0;
    sigval_state sigval = SIGVAL_UNKNOWN;
    int mok;
    char *subj = NULL;
    char *ski = NULL;

    // first, get the subject and the SKI
    /** @bug ignores error code without explanation */
    subj = X509_to_subject(cert, &sta, &x509sta);
    if (subj != NULL)
    {
        /** @bug ignores error code without explanation */
        ski = X509_to_ski(cert, &sta, &x509sta);
        if (ski != NULL)
        {
            sigval = get_sigval(thecon, OT_CER, subj, ski);
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
        /** @bug ignores error code without explanation */
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
static vfunc our_verify;
int
our_verify(
    X509_STORE_CTX *ctx)
{
    int mok;
    int n;
    int (*cb)(
        int,
        X509_STORE_CTX *);
    X509 *xsubject;
    X509 *xissuer;
    EVP_PKEY *pkey = NULL;

    cb = ctx->verify_cb;
    n = sk_X509_num(ctx->chain);
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

/**
 * @brief
 *     This is the routine that actually calls X509_verify_cert().
 *
 * Prior to calling the final verify function it performs the
 * following steps(+):
 *
 *   1. creates an X509_STORE_CTX
 *   2. sets the flags to 0
 *   3. initializes the CTX with the X509_STORE, X509 cert being
 *      checked, and the stack of untrusted X509 certs
 *   4. sets the trusted stack of X509 certs in the CTX
 *   5. sets the purpose in the CTX (which we had set outside of this
 *      function to the OpenSSL definition of "any")
 *   6. calls X509_verify_cert
 *
 * This function is modified from check() in apps/verify.c of the
 * OpenSSL source
 *
 * @param[in] e
 *     unused
 */
static err_code
checkit(
    scmcon *conp,
    X509_STORE *ctx,
    X509 *x,
    STACK_OF(X509) *uchain,
    STACK_OF(X509) *tchain,
    int purpose,
    ENGINE *e)
{
    LOG(LOG_DEBUG, "checkit(conp=%p, ctx=%p, x=%p"
        ", uchain=%p, tchain=%p, purpose=%d, e=%p)",
        conp, ctx, x, uchain, tchain, purpose, e);

    X509_STORE_CTX *csc;
    int i;
    err_code sta = 0;

    UNREFERENCED_PARAMETER(e);
    csc = X509_STORE_CTX_new();
    if (csc == NULL)
    {
        LOG(LOG_DEBUG, "X509_STORE_CTX_new() returned NULL");
        sta = ERR_SCM_STORECTX;
        goto done;
    }
    X509_STORE_set_flags(ctx, 0);
    if (!X509_STORE_CTX_init(csc, ctx, x, uchain))
    {
        LOG(LOG_DEBUG, "X509_STORE_CTX_init() returned 0");
        X509_STORE_CTX_free(csc);
        sta = ERR_SCM_STOREINIT;
        goto done;
    }
    if (tchain != NULL)
        X509_STORE_CTX_trusted_stack(csc, tchain);
    if (purpose >= 0)
        /** @bug ignores error codes (not 1) without explanation */
        X509_STORE_CTX_set_purpose(csc, purpose);
    old_vfunc = ctx->verify;
    thecon = conp;
    csc->verify = &our_verify;
    i = X509_verify_cert(csc);
    csc->verify = old_vfunc;
    old_vfunc = NULL;
    thecon = NULL;
    X509_STORE_CTX_free(csc);
    if (!i)
    {
        sta = ERR_SCM_NOTVALID;
    }
done:
    LOG(LOG_DEBUG, "checkit() returning %s: %s",
        err2name(sta), err2string(sta));
    return sta;
}

/**
 * @brief
 *     Read cert data from a file
 *
 * Unlike cert2fields(), this just fills in the X509 structure, not
 * the certfields
 *
 * @param[out] stap
 *     Error code.  On error, the value at this location is set to a
 *     non-zero value.  Otherwise, it is set to 0.  This parameter may
 *     be NULL.
 * @return
 *     NULL on error, non-NULL otherwise.
 */
static X509 *readCertFromFile(
    char *ofullname,
    err_code *stap)
{
    X509 *px = NULL;
    BIO *bcert = NULL;
    object_type typ;
    int x509sta;

    // open the file
    typ = infer_filetype(ofullname);
    bcert = BIO_new(BIO_s_file());
    if (bcert == NULL)
    {
        if (stap)
        {
            *stap = ERR_SCM_NOMEM;
        }
        return (NULL);
    }
    x509sta = BIO_read_filename(bcert, ofullname);
    if (x509sta <= 0)
    {
        BIO_free_all(bcert);
        if (stap)
        {
            *stap = ERR_SCM_X509;
        }
        return (NULL);
    }
    // read the cert based on the input type
    if (typ < OT_PEM_OFFSET)
        px = d2i_X509_bio(bcert, NULL);
    else
        px = PEM_read_bio_X509_AUX(bcert, NULL, NULL, NULL);
    BIO_free_all(bcert);
    if (stap)
    {
        if (px == NULL)
        {
            *stap = ERR_SCM_BADCERT;
        }
        else
        {
            *stap = 0;
        }
    }
    return (px);
}

static char parentAKI[SKISIZE];
static char parentIssuer[SUBJSIZE];

/**
 * @brief
 *     initialize an SQL search structure for certificate searches
 *
 * @param[out] certSrchp
 *     On success the value at this location will be set to the
 *     location of an initialized SQL search structure.  The caller is
 *     responsible for freeing the structure via freesrchscm().
 * @return
 *     0 on success, a non-zero error code otherwise.
 */
static err_code
init_certSrch(
    scmsrcha **certSrchp)
{
    LOG(LOG_DEBUG, "init_certSrch(certSrchp=%p)", certSrchp);

    err_code sta = 0;
    scmsrcha *certSrch = newsrchscm(NULL, 6, 0, 1);
    if (!certSrch)
    {
        LOG(LOG_ERR, "Unable to allocate memory to construct an SQL query");
        sta = ERR_SCM_NOMEM;
        goto done;
    }
    ADDCOL2(certSrch, "filename", SQL_C_CHAR, FNAMESIZE, sta, goto done);
    ADDCOL2(certSrch, "dirname", SQL_C_CHAR, DNAMESIZE, sta, goto done);
    ADDCOL2(certSrch, "flags", SQL_C_ULONG, sizeof(unsigned int), sta,
            goto done);
    ADDCOL2(certSrch, "aki", SQL_C_CHAR, SKISIZE, sta, goto done);
    ADDCOL2(certSrch, "issuer", SQL_C_CHAR, SUBJSIZE, sta, goto done);
    ADDCOL2(certSrch, "local_id", SQL_C_ULONG, sizeof(unsigned int), sta,
            goto done);

    assert(!sta);
    if (certSrchp)
    {
        *certSrchp = certSrch;
    }
    else
    {
        freesrchscm(certSrch);
    }
    certSrch = NULL;

done:
    if (sta && certSrch)
    {
        freesrchscm(certSrch);
    }
    LOG(LOG_DEBUG, "init_certSrch() returning %s: %s",
        err2name(sta), err2string(sta));
    return sta;
}

#define INIT_CERTSRCH(certSrch, sta, erraction)                         \
    do {                                                                \
        if ((certSrch) == NULL)                                         \
        {                                                               \
            sta = init_certSrch(&(certSrch));                           \
            LOG(LOG_DEBUG, "init_certSrch() returned %s: %s",           \
                err2name(sta), err2string(sta));                        \
            if (sta)                                                    \
            {                                                           \
                erraction;                                              \
            }                                                           \
            assert((certSrch));                                         \
        }                                                               \
    } while (0)

static sqlvaluefunc addCert2List;
err_code
addCert2List(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    UNREFERENCED_PARAMETER(conp);
    UNREFERENCED_PARAMETER(idx);
    assert(s);
    struct cert_answers *found_certs = s->context;
    assert(found_certs);
    assert(found_certs->num_ansrs >= 0);
    if (!found_certs->num_ansrs)
    {
        found_certs->cert_ansrp = calloc(1, sizeof(struct cert_ansr));
    }
    else
    {
        found_certs->cert_ansrp =
            realloc(found_certs->cert_ansrp,
                    sizeof(struct cert_ansr) * (found_certs->num_ansrs + 1));
    }
    /** @bug possible null pointer dereference if allocation failed */
    struct cert_ansr *this_ansrp =
        &found_certs->cert_ansrp[found_certs->num_ansrs++];
    memset(this_ansrp->dirname, 0, sizeof(this_ansrp->dirname));
    xstrlcpy(this_ansrp->dirname, (char *)s->vec[1].valptr,
             sizeof(this_ansrp->dirname));
    memset(this_ansrp->filename, 0, sizeof(this_ansrp->filename));
    xstrlcpy(this_ansrp->filename, (char *)s->vec[0].valptr,
             sizeof(this_ansrp->filename));
    memset(this_ansrp->fullname, 0, sizeof(this_ansrp->fullname));
    xsnprintf(this_ansrp->fullname, sizeof(this_ansrp->fullname), "%s/%s",
              (char *)s->vec[1].valptr, (char *)s->vec[0].valptr);
    memset(this_ansrp->issuer, 0, sizeof(this_ansrp->issuer));
    xstrlcpy(this_ansrp->issuer, (char *)s->vec[4].valptr,
             sizeof(this_ansrp->issuer));
    memset(this_ansrp->aki, 0, sizeof(this_ansrp->aki));
    xstrlcpy(this_ansrp->aki, (char *)s->vec[3].valptr,
             sizeof(this_ansrp->aki));
    this_ansrp->flags = *(unsigned int *)s->vec[2].valptr;
    this_ansrp->local_id = *(unsigned int *)s->vec[5].valptr;
    return 0;
}

/**
 * @brief
 *     find certificate(s) matching a SKI/subject
 *
 * @warning
 *     This function uses static memory and is not thread-safe.  Any
 *     call to this function overwrites the results returned from a
 *     previous call to this function.
 *
 * @param[in] conp
 *     Database connection.  This MUST NOT be NULL.
 * @param[in] ski
 *     The subject key identifier (SKI) of the certificate(s) to find.
 *     This MUST NOT be NULL.
 * @param[in] subject
 *     The subject of the certificate(s) to find.  This may be NULL,
 *     in which case only @p ski is used to perform the search.
 * @param[out] found_certsp
 *     On success, the value at this location will be set to point to
 *     a structure containing the certificates that match the given @p
 *     ski and @p subject.  The caller is responsible for free()ing
 *     the ::cert_ansrp member as well as the structure itself.  This
 *     parameter may be NULL.
 * @return
 *     0 on success, a non-zero error code otherwise.  Lack of matches
 *     is not considered to be an error.
 */
static err_code
find_certs(
    scmcon *conp,
    const char *ski,
    const char *subject,
    struct cert_answers **found_certsp)
{
    LOG(LOG_DEBUG, "find_certs(conp=%p, ski=\"%s\", subject=\"%s\""
        ", found_certsp=%p)",
        conp, ski, subject, found_certsp);

    err_code sta = 0;
    struct cert_answers *found_certs = NULL;
    static scmsrcha *certSrch = NULL;
    INIT_CERTSRCH(certSrch, sta, goto done);

    found_certs = malloc(sizeof(*found_certs));
    if (!found_certs)
    {
        LOG(LOG_ERR, "Unable to allocate memory to return matches");
        sta = ERR_SCM_NOMEM;
        goto done;
    }
    found_certs->cert_ansrp = NULL;
    found_certs->num_ansrs = 0;
    certSrch->context = found_certs;

    // find the entry whose subject is our issuer and whose ski is our aki,
    // e.g. our parent
    if (subject != NULL){
        char escaped [strlen(subject)*2+1];
        mysql_escape_string(escaped, subject, strlen(subject));
        xsnprintf(certSrch->wherestr, WHERESTR_SIZE,
                  "ski=\'%s\' and subject=\'%s\'", ski, escaped);
    }
    else
        xsnprintf(certSrch->wherestr, WHERESTR_SIZE, "ski=\'%s\'", ski);
    addFlagTest(certSrch->wherestr, SCM_FLAG_VALIDATED, 1, 1);
    addFlagTest(certSrch->wherestr, SCM_FLAG_NOCHAIN, 0, 1);

    sta = searchscm(conp, theCertTable, certSrch, NULL, &addCert2List,
                    SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);
    LOG(LOG_DEBUG, "searchscm() returned %s: %s",
        err2name(sta), err2string(sta));
    if (ERR_SCM_NODATA == sta)
    {
        assert(!found_certs->num_ansrs);
        sta = 0;
    }
    if (sta < 0)
    {
        goto done;
    }
    assert(found_certs->num_ansrs >= 0);
    LOG(LOG_DEBUG, "found %i matches", found_certs->num_ansrs);

    if (found_certsp)
    {
        *found_certsp = found_certs;
        // ownership has been handed off; prevent the cleanup below
        // from free()ing the found_certs structures
        found_certs = NULL;
    }

done:
    if (found_certs)
    {
        free(found_certs->cert_ansrp);
        free(found_certs);
    }
    LOG(LOG_DEBUG, "find_certs() returning %s: %s",
        err2name(sta), err2string(sta));
    return sta;
}

/**
 * @brief
 *     find a certificate matching a given SKI/subject
 *
 * If there are multiple matches, only one of them is returned (which
 * one is unspecified).
 *
 * @param[in] conp
 *     Database connection.  This MUST NOT be NULL.
 * @param[in] ski
 *     The subject key identifier (SKI) of the certificate to search
 *     for.  This MUST NOT be NULL.
 * @param[in] subject
 *     The subject of the certificate to search for.  This may be
 *     NULL, in which case only @p ski is used to perform the search.
 * @param[out] stap
 *     Error code.  On success the value at this location is set to 0.
 *     On error it is set to a non-zero value.  This parameter may be
 *     NULL.
 * @param[out] pathname
 *     If non-NULL, the full pathname of the matching certificate will
 *     be written to the buffer at this location.  The buffer must
 *     have size at least @c PATH_MAX.  This may be NULL.
 * @return
 *     NULL on error or if there is no match, otherwise it returns the
 *     matching cert.
 *
 * @note
 *     It is not an error if there are no matches or if there are
 *     multiple matches.  To distinguish an error from no matches,
 *     check the value at @p stap after this function returns.
 */
static X509 *
find_cert(
    scmcon *conp,
    char *ski,
    char *subject,
    err_code *stap,
    char *pathname,
    int *flagsp)
{
    LOG(LOG_DEBUG, "find_cert(conp=%p, ski=%s, subject=%s, stap=%p"
        ", pathname=%s, flagsp=%p)",
        conp, ski, subject, stap, pathname, flagsp);

    X509 *ret = NULL;
    err_code sta = 0;

    struct cert_answers *cert_answersp = NULL;
    sta = find_certs(conp, ski, subject, &cert_answersp);
    LOG(LOG_DEBUG, "find_certs() returned %s: %s",
        err2name(sta), err2string(sta));
    if (sta)
    {
        goto done;
    }
    assert(cert_answersp);
    struct cert_ansr *cert_ansrp = &cert_answersp->cert_ansrp[0];
    LOG(LOG_DEBUG, "got %i answers", cert_answersp->num_ansrs);
    assert(cert_answersp->num_ansrs >= 0);
    if (LOG_DEBUG <= LOG_LEVEL)
    {
        for (int i = 0; i < cert_answersp->num_ansrs; ++i)
        {
            struct cert_ansr *ansr = &cert_answersp->cert_ansrp[i];
            LOG(LOG_DEBUG, "  answer %i:", i);
            LOG(LOG_DEBUG, "    dirname=\"%s\"", ansr->dirname);
            LOG(LOG_DEBUG, "    filename=\"%s\"", ansr->filename);
            LOG(LOG_DEBUG, "    fullname=\"%s\"", ansr->fullname);
            LOG(LOG_DEBUG, "    aki=\"%s\"", ansr->aki);
            LOG(LOG_DEBUG, "    issuer=\"%s\"", ansr->issuer);
            LOG(LOG_DEBUG, "    flags=0x%x", ansr->flags);
            LOG(LOG_DEBUG, "    local_id=%u", ansr->local_id);
        }
    }
    if (!cert_answersp->num_ansrs)
    {
        /** @bug shouldn't sta be set to an error code? */
        goto done;
    }
    xstrlcpy(parentAKI, cert_ansrp->aki, sizeof(parentAKI));
    xstrlcpy(parentIssuer, cert_ansrp->issuer, sizeof(parentIssuer));
    if (pathname != NULL)
        strncpy(pathname, cert_ansrp->fullname, PATH_MAX);
    if (flagsp)
        *flagsp = cert_ansrp->flags;
    ret = readCertFromFile(cert_ansrp->fullname, &sta);
done:
    if (cert_answersp)
    {
        free(cert_answersp->cert_ansrp);
        free(cert_answersp);
    }
    LOG(LOG_DEBUG, "find_cert() returning %s: %s",
        err2name(sta), err2string(sta));
    if (stap)
    {
        *stap = sta;
    }
    return ret;
}

struct cert_answers *find_cert_by_aKI(
    char *ski,
    char *aki,
    scm *scmp,
    scmcon *conp)
{
    err_code sta = 0;
    static struct cert_answers cert_answers;
    struct cert_answers *found_certs = NULL;
    initTables(scmp);
    static scmsrcha *certSrch = NULL;
    INIT_CERTSRCH(certSrch, sta, return NULL);

    found_certs = &cert_answers;
    if (found_certs->cert_ansrp)
    {
        free(found_certs->cert_ansrp);
    }
    found_certs->cert_ansrp = NULL;
    found_certs->num_ansrs = 0;
    certSrch->context = found_certs;

    if (ski)
        xsnprintf(certSrch->wherestr, WHERESTR_SIZE, "ski=\'%s\'", ski);
    else
        xsnprintf(certSrch->wherestr, WHERESTR_SIZE, "aki=\'%s\'", aki);
    addFlagTest(certSrch->wherestr, SCM_FLAG_VALIDATED, 1, 1);
    addFlagTest(certSrch->wherestr, SCM_FLAG_NOCHAIN, 0, 1);

    sta = searchscm(conp, theCertTable, certSrch, NULL, &addCert2List,
                    SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);
    if (sta < 0)
    {
        found_certs->num_ansrs = sta;
    }
    return found_certs;
}

struct cert_answers *find_trust_anchors(
    scm *scmp,
    scmcon *conp)
{
    err_code sta = 0;
    static struct cert_answers cert_answers;
    struct cert_answers *found_certs = NULL;
    initTables(scmp);
    static scmsrcha *certSrch = NULL;
    INIT_CERTSRCH(certSrch, sta, return NULL);

    found_certs = &cert_answers;
    if (found_certs->cert_ansrp)
    {
        free(found_certs->cert_ansrp);
    }
    found_certs->cert_ansrp = NULL;
    found_certs->num_ansrs = 0;
    certSrch->context = found_certs;

    addFlagTest(certSrch->wherestr, SCM_FLAG_TRUSTED, 1, 0);

    sta = searchscm(conp, theCertTable, certSrch, NULL, &addCert2List,
                    SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);
    if (sta < 0)
    {
        found_certs->num_ansrs = sta;
    }
    return found_certs;
}

// static variables for efficiency, so only need to set up query once

static scmsrcha *revokedSrch = NULL;
static uint8_t *revokedSNList;
static unsigned int *revokedSNLen;

// static variables to pass to callback

static int isRevoked;
static uint8_t *revokedSN = NULL;

/**
 * @brief
 *     callback function for cert_revoked()
 */
static sqlvaluefunc revokedHandler;
err_code
revokedHandler(
    scmcon *conp,
    scmsrcha *s,
    ssize_t numLine)
{
    UNREFERENCED_PARAMETER(conp);
    UNREFERENCED_PARAMETER(s);
    UNREFERENCED_PARAMETER(numLine);
    unsigned int i;
    LOG(LOG_DEBUG, "number of revoked certs in CRL: %u", *revokedSNLen);
    for (i = 0; i < *revokedSNLen; i++)
    {
        uint8_t *entry = &revokedSNList[SER_NUM_MAX_SZ * i];
        if (LOG_DEBUG <= LOG_LEVEL)
        {
            char *x = hexify(SER_NUM_MAX_SZ, entry, HEXIFY_X);
            LOG(LOG_DEBUG, "  checking entry %u: %s", i, x);
            free(x);
        }
        if (memcmp(entry, revokedSN, SER_NUM_MAX_SZ) == 0)
        {
            isRevoked = 1;
            break;
        }
    }
    return 0;
}

/**
 * @brief
 *     Check whether a cert is revoked by a crl
 *
 * @return
 *     0 if the cert isn't revoked, ERR_SCM_REVOKED if the cert is
 *     revoked, or other error code
 */
static err_code
cert_revoked(
    scm *scmp,
    scmcon *conp,
    char *sn,
    char *issuer)
{
    LOG(LOG_DEBUG, "cert_revoked(scmp=%p, conp=%p, sn=\"%s\", issuer=\"%s\")",
        scmp, conp, sn, issuer);

    err_code sta = 0;
    int sn_len;

    // set up query once first time through and then just modify
    if (revokedSrch == NULL)
    {
        revokedSrch = newsrchscm(NULL, 2, 0, 1);
        initTables(scmp);
        ADDCOL(revokedSrch, "snlen", SQL_C_ULONG, sizeof(unsigned int),
               sta, sta);
        /** @bug magic number */
        ADDCOL(revokedSrch, "snlist", SQL_C_BINARY, 16 * 1024 * 1024, sta,
               sta);
        revokedSNLen = revokedSrch->vec[0].valptr;
        revokedSNList = revokedSrch->vec[1].valptr;
    }
    // query for crls such that issuer = issuer, and flags & valid
    // and set isRevoked = 1 in the callback if sn is in snlist
    char escaped [strlen(issuer)*2+1];
    mysql_escape_string(escaped, issuer, strlen(issuer));
    xsnprintf(revokedSrch->wherestr, WHERESTR_SIZE, "issuer=\"%s\"", escaped);
    addFlagTest(revokedSrch->wherestr, SCM_FLAG_VALIDATED, 1, 1);
    addFlagTest(revokedSrch->wherestr, SCM_FLAG_NOCHAIN, 0, 1);
    isRevoked = 0;
    sn_len = strlen(sn);
    if (sn_len != 2 + 2*SER_NUM_MAX_SZ) // "^x" followed by hex
    {
        sta = ERR_SCM_INVALARG;
        goto done;
    }
    revokedSN = unhexify(sn_len - 2, sn + 2); // 2 for the "^x" prefix
    if (revokedSN == NULL)
    {
        sta = ERR_SCM_NOMEM;
        goto done;
    }
    /** @bug ignores error code without explanation */
    sta = searchscm(conp, theCRLTable, revokedSrch, NULL, &revokedHandler,
                    SCM_SRCH_DOVALUE_ALWAYS, NULL);
    free(revokedSN);
    revokedSN = NULL;
    sta = isRevoked ? ERR_SCM_REVOKED : 0;

done:
    LOG(LOG_DEBUG, "cert_revoked() returning %s: %s",
        err2name(sta), err2string(sta));
    return sta;
}

/**
 * @brief
 *     Certificate verification code by mudge
 */
static err_code
verify_cert(
    scmcon *conp,
    X509 *x,
    int isTrusted,
    char *parentSKI,
    char *parentSubject,
    int *chainOK)
{
    LOG(LOG_DEBUG, "verify_cert(conp=%p, x=%p, isTrusted=%d, parentSKI=\"%s\""
        ", parentSubject=\"%s\", chainOK=%p)",
        conp, x, isTrusted, parentSKI, parentSubject, chainOK);

    STACK_OF(X509) *sk_trusted = NULL;
    STACK_OF(X509) *sk_untrusted = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    X509_STORE *cert_ctx = NULL;
    X509_LOOKUP *lookup = NULL;
    X509_PURPOSE *xptmp = NULL;
    X509 *parent = NULL;
    int purpose;
    int i;
    err_code sta = 0;

    // create X509 store
    cert_ctx = X509_STORE_new();
    if (cert_ctx == NULL)
    {
        LOG(LOG_DEBUG, "X509_STORE_new() returned NULL");
        sta = ERR_SCM_CERTCTX;
        goto done;
    }
    // set the verify callback
    X509_STORE_set_verify_cb_func(cert_ctx, verify_callback);
    // initialize the purpose
    /**
     * @bug ignores error codes from X509_PURPOSE_get_by_sname() (< 0)
     * without explanation
     */
    i = X509_PURPOSE_get_by_sname("any");
    /**
     * @bug ignores error code from X509_PURPOSE_get0() (NULL) without
     * explanation
     */
    xptmp = X509_PURPOSE_get0(i);
    purpose = X509_PURPOSE_get_id(xptmp);
    // setup the verification parameters
    /** @bug ignores error code (NULL) without explanation */
    vpm = (X509_VERIFY_PARAM *)X509_VERIFY_PARAM_new();
    /** @bug ignores error codes (not 1) without explanation */
    X509_VERIFY_PARAM_set_purpose(vpm, purpose);
    /** @bug ignores error codes (not 1) without explanation */
    X509_STORE_set1_param(cert_ctx, vpm);
    /**
     * @bug presumably X509_LOOKUP_file() could return NULL on error,
     * but that's unclear because the current implementation will
     * never return non-NULL
     */
    /**
     * @bug ignores error code from X509_STORE_add_lookup() (NULL)
     * without explanation
     */
    lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
    /**
     * @bug ignores error codes from X509_LOOKUP_load_file() (not 1)
     * without explanation
     */
    X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
    /**
     * @bug presumably X509_LOOKUP_hash_dir() could return NULL on
     * error, but that's unclear because the current implementation
     * will never return non-NULL
     */
    /**
     * @bug ignores error code from X509_STORE_add_lookup() (NULL)
     * without explanation
     */
    lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
    /**
     * @bug ignores error codes from X509_LOOKUP_add_dir() (not 1)
     * without explanation
     */
    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
    ERR_clear_error();
    // set up certificate stacks
    sk_trusted = sk_X509_new_null();
    if (sk_trusted == NULL)
    {
        LOG(LOG_DEBUG, "sk_X509_new_null() (for sk_trusted) returned NULL");
        X509_STORE_free(cert_ctx);
        X509_VERIFY_PARAM_free(vpm);
        sta = ERR_SCM_X509STACK;
        goto done;
    }
    sk_untrusted = sk_X509_new_null();
    if (sk_untrusted == NULL)
    {
        LOG(LOG_DEBUG, "sk_X509_new_null() (for sk_untrusted) returned NULL");
        sk_X509_free(sk_trusted);
        X509_STORE_free(cert_ctx);
        X509_VERIFY_PARAM_free(vpm);
        sta = ERR_SCM_X509STACK;
        goto done;
    }
    // if the certificate has already been flagged as trusted
    // just push it on the trusted stack and verify it
    *chainOK = 0;
    if (isTrusted)
    {
        *chainOK = 1;
        /** @bug ignores error code without explanation */
        sk_X509_push(sk_trusted, x);
    }
    else
    {
        int flags;
        /**
         * @bug
         *     find_cert()'s error code is not checked, so this logic
         *     does not distinguish an error from a parentless cert
         */
        parent =
            find_cert(conp, parentSKI, parentSubject, &sta, NULL, &flags);
        LOG(LOG_DEBUG, "find_cert() (for SKI/subject) error code is %s: %s",
            err2name(sta), err2string(sta));
        if (!parent)
        {
            LOG(LOG_DEBUG, "find_cert() returned NULL");
        }
        while (parent != NULL)
        {
            if (flags & SCM_FLAG_TRUSTED)
            {
                *chainOK = 1;
                /** @bug ignores error code without explanation */
                sk_X509_push(sk_trusted, parent);
                break;
            }
            else
            {
                /** @bug ignores error code without explanation */
                sk_X509_push(sk_untrusted, parent);
                /**
                 * @bug
                 *     find_cert()'s error code is not checked, so
                 *     this logic does not distinguish an error from a
                 *     parentless cert
                 */
                parent = find_cert(conp, parentAKI, parentIssuer, &sta, NULL,
                                     &flags);
                LOG(LOG_DEBUG, "find_cert() (for AKI/issuer) error code is"
                    " %s: %s", err2name(sta), err2string(sta));
                if (!parent)
                {
                    LOG(LOG_DEBUG, "find_cert() returned NULL");
                }
            }
        }
    }
    sta = 0;
    if (*chainOK)
    {
        sta =
            checkit(conp, cert_ctx, x, sk_untrusted, sk_trusted, purpose,
                    NULL);
        LOG(LOG_DEBUG, "checkit() returned %s: %s",
            err2name(sta), err2string(sta));
    }
    sk_X509_pop_free(sk_untrusted, X509_free);
    if (isTrusted)
    {
        // the caller retains ownership of x
        X509 *tmp = sk_X509_pop(sk_trusted);
        assert(tmp == x);
        assert(!sk_X509_num(sk_trusted));
    }
    sk_X509_pop_free(sk_trusted, X509_free);
    X509_STORE_free(cert_ctx);
    X509_VERIFY_PARAM_free(vpm);
done:
    LOG(LOG_DEBUG, "verify_cert() returning %s: %s",
        err2name(sta), err2string(sta));
    return (sta);
}

/**
 * @brief
 *     crl verification code
 *
 * @param[out] chainOK
 *     The value at this location will be set to true if a parent
 *     certificate was found, false otherwise.  Setting this to true
 *     does NOT mean that the CRL is valid, only that a parent cert
 *     was found.  This MUST NOT be NULL.
 * @return
 *     0 if no parent was found (regardless of any other properties of
 *     the CRL), or if a parent was found and the CRL validates
 *     against the parent.  Otherwise, this returns a non-zero error
 *     code.
 */
static err_code
verify_crl(
    scmcon *conp,
    X509_CRL *x,
    char *parentSKI,
    char *parentSubject,
    int *chainOK)
{
    int x509sta = 0;
    X509 *parent;
    EVP_PKEY *pkey;

    /**
     * @bug
     *     find_cert() only returns one match.  What if there are
     *     multiple matches?  (e.g., evil twin, cert renewal)
     */
    /** @bug ignores error code without explanation */
    parent = find_cert(conp, parentSKI, parentSubject, NULL, NULL, NULL);
    if (parent == NULL)
    {
        *chainOK = 0;
        /**
         * @bug
         *     Isn't it wrong to return success if no parent was
         *     found?  If so, fix it and update the return value
         *     documentation above.  If not, update the documentation
         *     above to clarify the semantics of this function and its
         *     return value.
         */
        return 0;
    }
    *chainOK = 1;
    pkey = X509_get_pubkey(parent);
    x509sta = X509_CRL_verify(x, pkey);
    X509_free(parent);
    EVP_PKEY_free(pkey);
    return (x509sta != 1) ? ERR_SCM_NOTVALID : 0;
}

/**
 * @brief
 *     roa utility
 *
 * @param[out] stap
 *     Error code.  This parameter MUST NOT be NULL.
 */
static unsigned char *readfile(
    char *fn,
    err_code *stap)
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

/**
 * @brief
 *     roa verification code
 *
 * @param[out] chainOK
 *     The value at this location will be set to true if a validated
 *     path to a trust anchor exists, false otherwise.  This MUST NOT
 *     be NULL.
 * @return
 *     0 if the ROA passes standalone validation checks (no checks
 *     against the parent cert) and either no parent cert is found or
 *     the path checks pass and there is no error.  Otherwise, a
 *     non-zero error code.
 */
static err_code
verify_roa(
    scmcon *conp,
    struct CMS *r,
    char *ski,
    int *chainOK)
{
    unsigned char *blob = NULL;
    X509 *cert;
    sigval_state sigval;
    err_code sta;
    char fn[PATH_MAX];

    // first, see if the ROA is already validated and in the DB
    sigval = get_sigval(conp, OT_ROA, ski, NULL);
    if (sigval == SIGVAL_VALID)
    {
        *chainOK = 1;
        return 0;
    }
    // next call the syntactic verification
    sta = roaValidate(r);
    if (sta < 0)
        return (sta);
    /**
     * @bug
     *     find_cert() only returns one match.  What if there are
     *     multiple matches?  (e.g., evil twin, cert renewal)
     */
    /** @bug ignores error code without explanation */
    cert = find_cert(conp, ski, NULL, &sta, fn, NULL);
    if (cert == NULL)
    {
        *chainOK = 0;
        /**
         * @bug
         *     Isn't it wrong to return success if the chain isn't OK?
         *     If so, fix it and update the return value documentation
         *     above.  If not, update the documentation above to
         *     clarify the semantics of this function and its return
         *     value.
         */
        return 0;
    }
    *chainOK = 1;
    // read the ASN.1 blob from the file
    blob = readfile(fn, &sta);
    /** @bug what if blob is NULL and sta is non-negative? */
    if (blob != NULL)
    {
        sta = roaValidate2(r);
        free((void *)blob);
    }
    X509_free(cert);
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

/**
 * @brief
 *     utility function for setting and zeroing the flags dealing with
 *     validation and validation staleness
 */
static err_code
updateValidFlags(
    scmcon *conp,
    scmtab *tabp,
    unsigned int id,
    unsigned int prevFlags,
    int isValid)
{
    char stmt[150];
    int flags = isValid ?
        ((prevFlags | SCM_FLAG_VALIDATED) & (~SCM_FLAG_NOCHAIN)) :
        (prevFlags | SCM_FLAG_NOCHAIN);
    xsnprintf(stmt, sizeof(stmt), "update %s set flags=%d where local_id=%d;",
              tabp->tabname, flags, id);
    return statementscm_no_data(conp, stmt);
}

// Used by rpwork
err_code
set_cert_flag(
    scmcon *conp,
    unsigned int id,
    unsigned int flags)
{
    char stmt[150];
    xsnprintf(stmt, sizeof(stmt), "update %s set flags=%d where local_id=%d;",
              theCertTable->tabname, flags, id);
    return statementscm_no_data(conp, stmt);
}

// Allowed CRL extension oids
// FIXME: move this to crl_profile_chk()
static struct goodoid goodoids[3];

static int make_goodoids(
    void)
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

/**
 * @brief
 *     callback function for verifyChildCert()
 */
static sqlvaluefunc verifyChildCRL;
err_code
verifyChildCRL(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    crl_fields *cf;
    X509_CRL *x = NULL;
    int crlsta = 0;
    err_code sta = 0;
    unsigned int i;
    unsigned int id;
    object_type typ;
    int chainOK;
    char pathname[PATH_MAX];

    UNREFERENCED_PARAMETER(idx);
    if (s->nused < 4)
        return ERR_SCM_INVALARG;

    if (!goodoids[0].lth)
        make_goodoids();
    // try verifying crl
    xsnprintf(pathname, PATH_MAX, "%s/%s", (char *)s->vec[0].valptr,
              (char *)s->vec[1].valptr);
    typ = infer_filetype(pathname);
    cf = crl2fields((char *)s->vec[1].valptr, pathname, typ,
                    &x, &sta, &crlsta, goodoids);
    if (cf == NULL)
        return sta;
    /** @bug ignores chainOK without explanation */
    sta = verify_crl(conp, x, cf->fields[CRF_FIELD_AKI],
                     cf->fields[CRF_FIELD_ISSUER], &chainOK);
    id = *((unsigned int *)(s->vec[2].valptr));
    // if invalid, delete it
    if (sta < 0)
    {
        /** @bug ignores error code without explanation */
        deletebylid(conp, theCRLTable, id);
        return sta;
    }
    // otherwise, validate it and do its revocations
    /** @bug ignores error code without explanation */
    sta = updateValidFlags(conp, theCRLTable, id,
                           *((unsigned int *)(s->vec[3].valptr)), 1);
    for (i = 0; i < cf->snlen; i++)
    {
        /** @bug ignores error code without explanation */
        revoke_cert_by_serial(theSCMP, conp, cf->fields[CRF_FIELD_ISSUER],
                              cf->fields[CRF_FIELD_AKI],
                              &((uint8_t *)cf->snlist)[SER_NUM_MAX_SZ * i]);
    }
    return 0;
}

/**
 * @brief
 *     callback function for verifyChildCert()
 */
static sqlvaluefunc verifyChildROA;
err_code
verifyChildROA(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    struct CMS roa;
    object_type typ;
    int chainOK;
    err_code sta;
    char pathname[PATH_MAX];
    char *skii;
    unsigned int id;

    UNREFERENCED_PARAMETER(idx);
    CMS(&roa, (ushort) 0);
    // try verifying crl
    xsnprintf(pathname, PATH_MAX, "%s/%s", (char *)s->vec[0].valptr,
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
        /** @bug ignores error code without explanation */
        deletebylid(conp, theROATable, id);
        return sta;
    }
    // otherwise, validate it
    /** @bug ignores error code without explanation */
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

/**
 * @brief
 *     the model revocation function for certificates
 *
 * This function handles the case where a certificate is expired or
 * revoked.  Given that this function can be called recursively it
 * must be careful in what it does.  If the top level certificate it
 * is handed has either the EXPIRED or REVOKED bit set in its flags
 * field, or the toplevel flag in the search context, then it is
 * deleted.  If none of these bits it set then it checks to see if it
 * has been reparented.  If it has not been reparented, it is deleted,
 * otherwise the function just returns.
 *
 * If a certificate is deleted, then this function is invoked recursively to
 * check to see if any of its children (certificate children or ROA children)
 * also need to be deleted.
 */
static sqlvaluefunc revoke_cert_and_children;

static sqlvaluefunc handleUpdateMan;
err_code
handleUpdateMan(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    (void)conp;
    (void)s;
    (void)idx;
    updateManLid = *((unsigned int *)updateManSrch->vec[1].valptr);
    xsnprintf(updateManPath, PATH_MAX, "%s/",
              (char *)updateManSrch->vec[0].valptr);
    xsnprintf(updateManHash, HASHSIZE, "%s",
              (char *)updateManSrch->vec[2].valptr);
    return 0;
}

static err_code
updateManifestObjs(
    scmcon *conp,
    struct Manifest *manifest)
{
    struct FileAndHash *fahp = NULL;
    uchar file[NAME_MAX + 1];
    char escaped_file[NAME_MAX * 2 + 1];
    uchar bytehash[HASHSIZE / 2];
    uchar *bhash;
    scmtab *tabp;
    char flagStmt[200 + HASHSIZE];
    int bhashlen;
    int gothash;
    err_code sta;
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
        int hashlen;
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
        else if (strstr((char *)file, ".gbr"))
            tabp = theGBRTable;
        else
            continue;
        mysql_escape_string(escaped_file, (char *)file, strlen((char *)file));
        xsnprintf(updateManSrch->wherestr, WHERESTR_SIZE, "filename=\"%s\"",
                  escaped_file);
        addFlagTest(updateManSrch->wherestr, SCM_FLAG_ONMAN, 0, 1);
        updateManLid = 0;
        memset(updateManHash, 0, sizeof(updateManHash));
        /** @bug ignores error code without explanation */
        searchscm(conp, tabp, updateManSrch, NULL, &handleUpdateMan,
                  SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);
        if (!updateManLid)
            continue;
        len = strlen(updateManPath);
        xsnprintf(updateManPath + len, PATH_MAX - len, "%s", file);
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
                /**
                 * @bug
                 *     there are many ways bhash could end up NULL; is
                 *     this really the most appropriate error code?
                 */
                hashlen = ERR_SCM_BADMFTDBHASH;
            else
            {
                bhashlen /= 2;
                memcpy(bytehash, bhash, bhashlen);
                free(bhash);
                hashlen =
                    check_fileAndHash(fahp, fd, bytehash, bhashlen,
                                      HASHSIZE / 2);
            }
        }
        else
        {
            gothash = 0;
            memset(bytehash, 0, sizeof(bytehash));
            hashlen = check_fileAndHash(fahp, fd, bytehash, 0, HASHSIZE / 2);
        }
        (void)close(fd);
        if (hashlen >= 0)
        {
            // if hash okay, set ONMAN flag and optionally the hash if we just
            // computed it
            if (gothash == 1)
                xsnprintf(flagStmt, sizeof(flagStmt),
                          "update %s set flags=flags+%d where local_id=%d;",
                          tabp->tabname, SCM_FLAG_ONMAN, updateManLid);
            else
            {
                char *h = hexify(hashlen, bytehash, HEXIFY_NO);
                xsnprintf(flagStmt, sizeof(flagStmt),
                          "update %s set flags=flags+%d, hash=\"%s\""
                          " where local_id=%d;",
                          tabp->tabname, SCM_FLAG_ONMAN, h, updateManLid);
                free(h);
            }
            /** @bug ignores error code without explanation */
            statementscm_no_data(conp, flagStmt);
        }
        else
        {
            /**
             * @bug
             *     There are many ways check_fileAndHash() could fail,
             *     and perhaps not all of them mean that the file's
             *     hash is bad (e.g., maybe there was a crypto library
             *     problem).  Thus, deleting the object and
             *     invalidating its children might not be the correct
             *     action to take.
             */
            LOG(LOG_ERR, "Hash not ok on file %s", file);
            // if hash not okay, delete object, and if cert, invalidate
            // children
            if (tabp == theCertTable)
            {
                xsnprintf(updateManSrch2->wherestr, WHERESTR_SIZE,
                          "local_id=\"%d\"", updateManLid);
                /** @bug ignores error code without explanation */
                searchscm(conp, tabp, updateManSrch2, NULL,
                          &revoke_cert_and_children, SCM_SRCH_DOVALUE_ALWAYS,
                          NULL);
            }
            else
            {
                /** @bug ignores error code without explanation */
                deletebylid(conp, tabp, updateManLid);
            }
        }
    }
    return 0;
}

/**
 * @brief
 *     callback function for verifyChildCert()
 */
static sqlvaluefunc verifyChildManifest;
err_code
verifyChildManifest(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    struct CMS cms;
    char outfull[PATH_MAX];
    UNREFERENCED_PARAMETER(idx);
    /** @bug ignores error code without explanation */
    updateValidFlags(conp, theManifestTable,
                     *((unsigned int *)(s->vec[0].valptr)),
                     *((unsigned int *)(s->vec[1].valptr)), 1);
    CMS(&cms, 0);
    xsnprintf(outfull, PATH_MAX, "%s/%s", (char *)(s->vec[2].valptr),
              (char *)(s->vec[3].valptr));
    if (get_casn_file(&cms.self, outfull, 0) < 0)
    {
        delete_casn(&cms.self);
        LOG(LOG_ERR, "invalid manifest filename %s", outfull);
        /** @bug use a better error code */
        return ERR_SCM_UNSPECIFIED;
    }
    struct Manifest *manifest =
        &cms.content.signedData.encapContentInfo.eContent.manifest;
    /** @bug ignores error code without explanation */
    updateManifestObjs(conp, manifest);
    delete_casn(&cms.self);
    return 0;
}

/**
 * @brief
 *     callback function for verifyChildCert()
 *
 * This is used, for example, to mark GBRs as valid when their EE
 * certs become valid.
 */
static sqlvaluefunc verifyChildGhostbusters;
err_code
verifyChildGhostbusters(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    (void)idx;

    /** @bug ignores error code without explanation */
    updateValidFlags(conp, theGBRTable,
                     *((unsigned int *)(s->vec[2].valptr)),
                     *((unsigned int *)(s->vec[3].valptr)), 1);

    return 0;
}

/**
 * @brief
 *     structure containing data of children to propagate
 */
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

/**
 * @brief
 *     static variables for efficiency, so only need to set up query
 *     once
 */
static scmsrcha *crlSrch = NULL;
static scmsrcha *manSrch = NULL;

/**
 * @brief
 *     single place to allocate large amount of space for manifest
 *     files lists
 */
static char manFiles[MANFILES_SIZE];

/**
 * @brief
 *     utility function for verifyOrNotChildren()
 */
static err_code
verifyChildCert(
    scmcon *conp,
    PropData *data,
    int doVerify)
{
    LOG(LOG_DEBUG, "verifyChildCert(conp=%p"
        ", data=%p{.ski=\"%s\", .subject=\"%s\"}, doVerify=%i)",
        conp, data, data->ski, data->subject, doVerify);

    X509 *x = NULL;
    err_code sta;
    int chainOK;
    char pathname[PATH_MAX];

    if (doVerify)
    {
        xsnprintf(pathname, PATH_MAX, "%s/%s", data->dirname, data->filename);
        /** @bug ignores error code without explanation */
        x = readCertFromFile(pathname, &sta);
        if (x == NULL)
        {
            sta = ERR_SCM_X509;
            goto done;
        }
        /** @bug ignores chainOK without explanation */
        sta = verify_cert(conp, x, 0, data->aki, data->issuer, &chainOK);
        if (sta < 0)
        {
            LOG(LOG_ERR, "Child cert %s is not valid", pathname);
            /** @bug ignores error code without explanation */
            deletebylid(conp, theCertTable, data->id);
            goto done;
        }
        /** @bug ignores error code without explanation */
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
    xsnprintf(crlSrch->wherestr, WHERESTR_SIZE,
              "aki=\"%s\" and issuer=\"%s\"", data->ski, data->subject);
    addFlagTest(crlSrch->wherestr, SCM_FLAG_NOCHAIN, 1, 1);
    /** @bug ignores error code without explanation */
    sta = searchscm(conp, theCRLTable, crlSrch, NULL, &verifyChildCRL,
                    SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);

    /* Check for associated GBRs */
    xsnprintf(crlSrch->wherestr, WHERESTR_SIZE, "ski=\"%s\"", data->ski);
    /** @bug ignores error code without explanation */
    searchscm(conp, theGBRTable, crlSrch, NULL, &verifyChildGhostbusters,
              SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);

    /* Check for associated ROA */
    xsnprintf(crlSrch->wherestr, WHERESTR_SIZE, "ski=\"%s\"", data->ski);
    addFlagTest(crlSrch->wherestr, SCM_FLAG_NOCHAIN, 1, 1);
    /** @bug ignores error code without explanation */
    sta = searchscm(conp, theROATable, crlSrch, NULL, &verifyChildROA,
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
    xsnprintf(manSrch->wherestr, WHERESTR_SIZE, "ski=\"%s\"", data->ski);
    /** @bug ignores error code without explanation */
    sta = searchscm(conp, theManifestTable, manSrch, NULL, &verifyChildManifest,
                    SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);
    sta = 0;
done:
    X509_free(x);
    LOG(LOG_DEBUG, "verifyChildCert() returning %s: %s",
        err2name(sta), err2string(sta));
    return sta;
}

typedef struct _mcf {
    int did;
    int toplevel;
} mcf;


/**
 * @brief
 *     returns the number of valid certificates that have subject=IS
 *     and ski=AK, or a negative error code on failure.
 */
static sqlvaluefunc cparents;
err_code
cparents(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    UNREFERENCED_PARAMETER(conp);
    UNREFERENCED_PARAMETER(idx);
    mcf *mymcf = (mcf *)(s->context);
    // ???????????? don't have this function, instead use where clause ?????
    mymcf->did++;
    return (0);
}

/**
 * @return
 *     number of valid parents on success (non-negative), error code
 *     on failure (negative).  The @c err_code type is not used as the
 *     return value type because the C standard allows enum types to
 *     be smaller than @c int (even though the enumeration constants
 *     themselves always have type int), which would limit this
 *     function's range of returnable values.
 */
static int countvalidparents(
    scmcon *conp,
    char *IS,
    char *AK)
{
    // ?????? replace this with shorter version using utility funcs ????????
    unsigned int flags = 0;
    scmkv w[2];
    mcf mymcf;
    char ws[256];
    char *now;
    err_code sta;
    char escaped[(IS != NULL) ? strlen(IS)*2+1 : 0];

    w[0] = (scmkv){"ski", AK};
    if (IS != NULL)
    {
        mysql_escape_string(escaped, IS, strlen(IS));
        w[1] = (scmkv){"subject", escaped};
    }
    scmkva where = {
        .vec = w,
        .ntot = (IS == NULL) ? 1 : 2,
        .nused = (IS == NULL) ? 1 : 2,
        .vald = 0,
    };
    scmsrch srch1[] = {
        {
            .colno = 1,
            .sqltype = SQL_C_ULONG,
            .colname = "flags",
            .valptr = &flags,
            .valsize = sizeof(flags),
            .avalsize = 0,
        },
    };
    now = LocalTimeToDBTime(&sta);
    if (now == NULL)
        return (sta);
    xsnprintf(ws, sizeof(ws), "valfrom < \"%s\" AND \"%s\" < valto", now, now);
    free(now);
    addFlagTest(ws, SCM_FLAG_VALIDATED, 1, 1);
    addFlagTest(ws, SCM_FLAG_NOCHAIN, 0, 1);
    mymcf.did = 0;
    scmsrcha srch = {
        .vec = srch1,
        .sname = NULL,
        .ntot = ELTS(srch1),
        .nused = ELTS(srch1),
        .vald = 0,
        .where = &where,
        .wherestr = ws,
        .context = &mymcf,
    };
    sta = searchscm(conp, theCertTable, &srch, NULL, &cparents,
                    SCM_SRCH_DOVALUE_ALWAYS, NULL);
    if (sta < 0)
        return (sta);
    return mymcf.did;
}

// static variables for efficiency, so only need to set up query once

static scmsrcha *roaSrch = NULL;
static scmsrcha *invalidateCRLSrch = NULL;

/**
 * @brief
 *     callback function for invalidateChildCert()
 */
static sqlvaluefunc invalidate_roa;
err_code
invalidate_roa(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    unsigned int lid,
        flags;
    char ski[512];

    UNREFERENCED_PARAMETER(idx);
    lid = *(unsigned int *)(s->vec[0].valptr);
    flags = *(unsigned int *)(s->vec[2].valptr);
    (void)strncpy(ski, (char *)(s->vec[1].valptr), 512);
    /** @bug ignores error code without explanation */
    if (countvalidparents(conp, NULL, ski) > 0)
        return (0);
    /** @bug ignores error code without explanation */
    updateValidFlags(conp, theROATable, lid, flags, 0);
    return 0;
}

/**
 * @brief
 *     callback function for invalidateChildCert()
 */
static sqlvaluefunc invalidate_gbr;
err_code
invalidate_gbr(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    char ski[512];

    (void)idx;

    strncpy(ski, (char *)(s->vec[1].valptr), sizeof(ski));
    /** @bug ignores error code without explanation */
    if (countvalidparents(conp, NULL, ski) > 0)
    {
        return 0;
    }

    /** @bug ignores error code without explanation */
    updateValidFlags(conp, theGBRTable, *(unsigned int *)(s->vec[0].valptr),
                     *(unsigned int *)(s->vec[2].valptr), 0);

    return 0;
}

/**
 * @brief
 *     callback function for invalidateChildCert()
 */
static sqlvaluefunc invalidate_mft;
err_code
invalidate_mft(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    char ski[512];

    (void)idx;

    strncpy(ski, (char *)(s->vec[1].valptr), sizeof(ski));
    /** @bug ignores error code without explanation */
    if (countvalidparents(conp, NULL, ski) > 0)
    {
        return 0;
    }

    /** @bug ignores error code without explanation */
    updateValidFlags(conp, theManifestTable,
                     *(unsigned int *)(s->vec[0].valptr),
                     *(unsigned int *)(s->vec[2].valptr), 0);

    /*
        TODO: How should invalidating a manifest affect objects listed on the
              manifest?

        Removing the ONMAN flag is too naive because another MFT could correctly
        list the same files. This approach would be especially problematic in
        the case of a new MFT being added before the old one is invalidated.

        It's probably better to put this problem off until there's more clarity
        from the working group about how exactly to handle manifests and all of
        their fun corner cases.
    */

    return 0;
}

/**
 * @brief
 *     callback function for invalidateChildCert()
 */
static sqlvaluefunc invalidate_crl;
err_code
invalidate_crl(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    char aki[SKISIZE + 1];
    char issuer[SUBJSIZE + 1];

    (void)idx;

    strncpy(aki, (char *)(s->vec[1].valptr), sizeof(aki));
    strncpy(issuer, (char *)(s->vec[2].valptr), sizeof(issuer));
    /** @bug ignores error code without explanation */
    if (countvalidparents(conp, issuer, aki) > 0)
    {
        return 0;
    }

    /** @bug ignores error code without explanation */
    updateValidFlags(conp, theCRLTable,
                     *(unsigned int *)(s->vec[0].valptr),
                     *(unsigned int *)(s->vec[3].valptr), 0);

    // NOTE: Once a cert is revoked, it shouldn't become "un-revoked."

    return 0;
}

/**
 * @brief
 *     utility function for verifyOrNotChildren()
 */
static err_code
invalidateChildCert(
    scmcon *conp,
    PropData *data,
    int doUpdate)
{
    err_code sta;

    if (doUpdate)
    {
        /** @bug ignores error code without explanation */
        if (countvalidparents(conp, data->issuer, data->aki) > 0)
            return ERR_SCM_UNSPECIFIED;
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
    xsnprintf(roaSrch->wherestr, WHERESTR_SIZE, "ski=\"%s\"", data->ski);
    addFlagTest(roaSrch->wherestr, SCM_FLAG_NOCHAIN, 0, 1);

    if (invalidateCRLSrch == NULL)
    {
        invalidateCRLSrch = newsrchscm(NULL, 4, 0, 1);
        ADDCOL(invalidateCRLSrch, "local_id", SQL_C_ULONG, sizeof(unsigned int),
               sta, sta);
        ADDCOL(invalidateCRLSrch, "aki", SQL_C_CHAR, SKISIZE, sta, sta);
        ADDCOL(invalidateCRLSrch, "issuer", SQL_C_CHAR, SUBJSIZE, sta, sta);
        ADDCOL(invalidateCRLSrch, "flags", SQL_C_ULONG, sizeof(unsigned int),
               sta, sta);
    }
    char escaped[strlen(data->subject)*2+1];
    mysql_escape_string(escaped, data->subject, strlen(data->subject));
    xsnprintf(invalidateCRLSrch->wherestr, WHERESTR_SIZE,
              "aki=\"%s\" AND issuer=\"%s\"", data->ski, escaped);
    addFlagTest(invalidateCRLSrch->wherestr, SCM_FLAG_NOCHAIN, 0, 1);


    /** @bug ignores error code without explanation */
    searchscm(conp, theROATable, roaSrch, NULL, &invalidate_roa,
              SCM_SRCH_DOVALUE_ALWAYS, NULL);

    // reuse roaSrch for GBRs because the columns are the same
    /** @bug ignores error code without explanation */
    searchscm(conp, theGBRTable, roaSrch, NULL, &invalidate_gbr,
              SCM_SRCH_DOVALUE_ALWAYS, NULL);

    // reuse roaSrch for MFTs because the columns are the same
    /** @bug ignores error code without explanation */
    searchscm(conp, theManifestTable, roaSrch, NULL, &invalidate_mft,
              SCM_SRCH_DOVALUE_ALWAYS, NULL);

    /** @bug ignores error code without explanation */
    searchscm(conp, theCRLTable, invalidateCRLSrch, NULL, &invalidate_crl,
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

/**
 * @brief
 *     callback function for verifyOrNotChildren()
 */
static sqlvaluefunc registerChild;
err_code
registerChild(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    LOG(LOG_DEBUG, "registerChild(conp=%p, scmsrcha=%p, idx=%zi)",
        conp, s, idx);

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

    err_code sta = 0;
    LOG(LOG_DEBUG, "registerChild() returning %s: %s",
        err2name(sta), err2string(sta));
    return sta;
}

/**
 * @brief
 *     verify the children certs of the current cert
 */
static err_code
verifyOrNotChildren(
    scmcon *conp,
    char *ski,
    char *subject,
    char *aki,
    char *issuer,
    unsigned int cert_id,
    int doVerify)
{
    LOG(LOG_DEBUG, "verifyOrNotChildren(conp=%p, ski=\"%s\", subject=\"%s\""
        ", aki=\"%s\", issuer=\"%s\", cert_id=%u, doVerify=%i)",
        conp, ski, subject, aki, issuer, cert_id, doVerify);

    int isRoot = 1;
    int doIt;
    int idx;
    err_code sta = 0;

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
            /** @bug ignores error code without explanation */
            doIt =
                verifyChildCert(conp, &currPropData->data[idx], !isRoot) == 0;
        else
            /** @bug ignores error code without explanation */
            doIt =
                invalidateChildCert(conp, &currPropData->data[idx],
                                    !isRoot) == 0;
        LOG(LOG_DEBUG, "doIt=%i", doIt);
        if (doIt)
        {
            char escaped [strlen(currPropData->data[idx].subject)*2+1];
            mysql_escape_string(escaped, currPropData->data[idx].subject,
                                strlen(currPropData->data[idx].subject));

            xsnprintf(childrenSrch->wherestr, WHERESTR_SIZE,
                      "aki=\"%s\" and ski<>\"%s\" and issuer=\"%s\"",
                      currPropData->data[idx].ski, currPropData->data[idx].ski,
                      escaped);
            /**
             * @bug
             *     This WHERE clause addition skips children that are
             *     not valid (doVerify) or valid (!doVerify), and thus
             *     their descendants are not processed.  While it's OK
             *     to skip descendants that are already valid
             *     (doVerify) or invalid (!doVerify), each invalid
             *     (doVerify) or valid (!doVerify) descendant must be
             *     processed to handle cases like this doVerify
             *     example:
             *
             *     @verbatim
             *         already valid cert   newly validated cert
             *         with resources X,Y   with resources X,Y,Z
             *                 |                     |
             *                 +----------+----------+
             *                            |
             *                    already valid cert
             *                 with inherited resources
             *                            |
             *                            |
             *                       invalid cert
             *                    with resources Y,Z
             *                 that should now be valid
             *     @endverbatim
             */
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
            /** @bug ignores error code without explanation */
            searchscm(conp, theCertTable, childrenSrch, NULL, &registerChild,
                      SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);
        isRoot = 0;
    }
    currPropData = prevPropData;

    LOG(LOG_DEBUG, "verifyOrNotChildren() returning %s: %s",
        err2name(sta), err2string(sta));
    return sta;
}

/*
 * primarily, do check for whether there already is a valid manifest
 * that can either confirm or deny the hash
 */

static scmsrcha *validManSrch = NULL;
static char validManPath[PATH_MAX];

static sqlvaluefunc handleValidMan;
err_code
handleValidMan(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    (void)conp;
    (void)idx;
    xsnprintf(validManPath, PATH_MAX, "%s/%s", (char *)s->vec[0].valptr,
              (char *)s->vec[1].valptr);
    return 0;
}

err_code
addStateToFlags(
    unsigned int *flags,
    int isValid,
    char *filename,
    char *fullpath,
    scm *scmp,
    scmcon *conp)
{
    err_code sta;
    int fd;
    struct CMS cms;
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
    xsnprintf(validManSrch->wherestr, WHERESTR_SIZE,
              "files regexp binary \"%s\"", filename);
    addFlagTest(validManSrch->wherestr, SCM_FLAG_VALIDATED, 1, 1);
    initTables(scmp);
    validManPath[0] = 0;
    /** @bug ignores error code without explanation */
    searchscm(conp, theManifestTable, validManSrch, NULL, &handleValidMan,
              SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN, NULL);
    if (!validManPath[0])
        return 0;

    CMS(&cms, 0);
    /** @bug ignores error code without explanation */
    get_casn_file(&cms.self, validManPath, 0);
    struct Manifest *manifest =
        &cms.content.signedData.encapContentInfo.eContent.manifest;
    simple_constructor(&ccasn, (ushort)0, ASN_IA5_STRING);
    write_casn(&ccasn, (uchar *)filename, strlen(filename));
    for (fahp = (struct FileAndHash *)member_casn(&manifest->fileList.self, 0);
         fahp && diff_casn(&fahp->file, &ccasn);
         fahp = (struct FileAndHash *)next_of(&fahp->self));
    int wsta = 0;
    if (fahp && (fd = open(fullpath, O_RDONLY)) >= 0)
    {
        *flags |= SCM_FLAG_ONMAN;
        wsta = check_fileAndHash(fahp, fd, NULL, 0, 0);
        (void)close(fd);
    }
    delete_casn(&ccasn);
    delete_casn(&cms.self);
    return wsta >= 0 ? 0 : wsta;
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

static err_code
add_cert_2(
    scm *scmp,
    scmcon *conp,
    cert_fields *cf,
    X509 *x,
    unsigned int id,
    int utrust,
    unsigned int *cert_id,
    char *fullpath)
{
    LOG(LOG_DEBUG, "add_cert_2(scmp=%p, conp=%p, cf=%p, x=%p, id=%u"
        ", utrust=%d, cert_id=%p, fullpath=%s)",
        scmp, conp, cf, x, id, utrust, cert_id, fullpath);

    err_code sta = 0;
    int chainOK;
    int ct = UN_CERT;

    cf->dirid = id;
    struct Certificate cert;
    Certificate(&cert, (ushort)0);
    struct Extension *ski_extp;
    struct Extension *aki_extp;
    err_code locerr = 0;
    if (get_casn_file(&cert.self, fullpath, 0) < 0)
    {
        LOG(LOG_DEBUG, "get_casn_file() returned an error code");
        locerr = ERR_SCM_BADCERT;
    }
    else if (!(ski_extp = find_extension(&cert.toBeSigned.extensions,
                                         id_subjectKeyIdentifier, false)))
    {
        LOG(LOG_DEBUG, "no SKI extension found");
        locerr = ERR_SCM_NOSKI;
    }
    if (locerr)
    {
        delete_casn(&cert.self);
        sta = locerr;
        goto done;
    }
    if (utrust > 0)
    {
        if ((aki_extp = find_extension(&cert.toBeSigned.extensions,
                                       id_authKeyId, false)) &&
            diff_casn(&ski_extp->extnValue.subjectKeyIdentifier,
                      &aki_extp->extnValue.authKeyId.keyIdentifier))
        {
            LOG(LOG_DEBUG, "either no AKI extension found or SKI != AKI");
            locerr = 1;
        }
        else if (strcmp(cf->fields[CF_FIELD_SUBJECT],
                        cf->fields[CF_FIELD_ISSUER]) != 0)
        {
            LOG(LOG_DEBUG, "subject and issuer don't match");
            locerr = 1;
        }
        else if (vsize_casn(&cert.signature) < 256)
        {
            LOG(LOG_DEBUG, "signature too small");
            locerr = ERR_SCM_SMALLKEY;
        }
        else if (vsize_casn(&cert.toBeSigned.subjectPublicKeyInfo.
                            subjectPublicKey) < 265)
        {
            LOG(LOG_DEBUG, "key too small");
            locerr = ERR_SCM_SMALLKEY;
        }
        if (locerr)
        {
            delete_casn(&cert.self);
            sta = (locerr < 0) ? locerr : ERR_SCM_NOTSS;
            goto done;
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
    if (sta)
    {
        LOG(LOG_DEBUG, "rescert_profile_chk() returned %s: %s",
            err2name(sta), err2string(sta));
        goto done;
    }
    // MCR: new code to check for expiration. Ignore this
    // check if "allowex" is non-zero
    if (allowex == 0)
    {
        if (X509_cmp_time(X509_get_notAfter(x), NULL) < 0)
        {
            LOG(LOG_DEBUG, "expired");
            sta = ERR_SCM_EXPIRED;
            goto done;
        }
    }
    // Check if cert isn't valid yet, i.e. notBefore is in the future.
    if (X509_cmp_time(X509_get_notBefore(x), NULL) > 0)
    {
        LOG(LOG_WARNING, "Certificate notBefore is in the future");
        cf->flags |= SCM_FLAG_NOTYET;
    }
    // MCR
    // verify the cert
    if ((sta = verify_cert(conp, x, utrust, cf->fields[CF_FIELD_AKI],
                           cf->fields[CF_FIELD_ISSUER], &chainOK)))
    {
        LOG(LOG_DEBUG, "verify_cert() returned %s: %s",
            err2name(sta), err2string(sta));
        goto done;
    }
    // check that no crls revoking this cert
    if ((sta = cert_revoked(scmp, conp, cf->fields[CF_FIELD_SN],
                            cf->fields[CF_FIELD_ISSUER])))
    {
        LOG(LOG_DEBUG, "cert_revoked() returned %s: %s",
            err2name(sta), err2string(sta));
        goto done;
    }
    // actually add the certificate
    if ((sta = addStateToFlags(&cf->flags, chainOK,
                               cf->fields[CF_FIELD_FILENAME],
                               fullpath, scmp, conp)))
    {
        LOG(LOG_DEBUG, "addStateToFlags() returned %s: %s",
            err2name(sta), err2string(sta));
        goto done;
    }
    if ((sta = add_cert_internal(scmp, conp, cf, cert_id)))
    {
        LOG(LOG_DEBUG, "add_cert_internal() returned %s: %s",
            err2name(sta), err2string(sta));
        goto done;
    }
    // try to validate children of cert
    if (chainOK)
    {
        if ((sta = verifyOrNotChildren(conp, cf->fields[CF_FIELD_SKI],
                                       cf->fields[CF_FIELD_SUBJECT],
                                       cf->fields[CF_FIELD_AKI],
                                       cf->fields[CF_FIELD_ISSUER],
                                       *cert_id, 1)))
        {
            LOG(LOG_DEBUG, "verifyOrNotChildren() returned %s: %s",
                err2name(sta), err2string(sta));
            goto done;
        }
    }
done:
    LOG(LOG_DEBUG, "add_cert_2() returning %s: %s",
        err2name(sta), err2string(sta));
    return (sta);
}

err_code
add_cert(
    scm *scmp,
    scmcon *conp,
    char *outfile,
    char *outfull,
    unsigned int id,
    int utrust,
    object_type typ,
    unsigned int *cert_id)
{
    LOG(LOG_DEBUG, "add_cert(scmp=%p, conp=%p, outfile=\"%s\""
        ", outfull=\"%s\", id=%u, utrust=%d, typ=%d"
        ", cert_id=%p)",
        scmp, conp, outfile, outfull, id, utrust, typ, cert_id);

    cert_fields *cf;
    X509 *x = NULL;
    int x509sta = 0;
    err_code sta = 0;

    initTables(scmp);
    /** @bug ignores error code without explanation if cf && x */
    /** @bug ignores x509sta without explanation */
    cf = cert2fields(outfile, outfull, typ, &x, &sta, &x509sta);
    LOG(LOG_DEBUG, "cert2fields() returned error code %s: %s",
        err2name(sta), err2string(sta));
    if (cf == NULL || x == NULL)
    {
        goto done;
    }
    sta = add_cert_2(scmp, conp, cf, x, id, utrust, cert_id, outfull);
    LOG(LOG_DEBUG, "add_cert_2() returned error code %s: %s",
        err2name(sta), err2string(sta));
done:
    freecf(cf);
    X509_free(x);
    LOG(LOG_DEBUG, "add_cert() returning %s: %s",
        err2name(sta), err2string(sta));
    return sta;
}

err_code
add_crl(
    scm *scmp,
    scmcon *conp,
    char *outfile,
    char *outfull,
    unsigned int id,
    int utrust,
    object_type typ)
{
    LOG(LOG_DEBUG, "add_crl(scmp=%p, conp=%p, outfile=\"%s\""
        ", outfull=\"%s\", id=%u, utrust=%i, typ=%i)",
        scmp, conp, outfile, outfull, id, utrust, typ);

    crl_fields *cf;
    X509_CRL *x = NULL;
    int crlsta = 0;
    err_code sta = 0;
    unsigned int i;
    int chainOK;
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
        sta = ERR_SCM_INVALASN;
        goto done;
    }
    if ((sta = crl_profile_chk(&crl)) != 0)
    {
        LOG(LOG_ERR, "CRL failed standalone profile check: %s", outfile);
        delete_casn(&crl.self);
        goto done;
    }
    delete_casn(&crl.self);

    cf = crl2fields(outfile, outfull, typ, &x, &sta, &crlsta, goodoids);
    if (cf == NULL || x == NULL)
    {
        if (cf != NULL)
            freecrf(cf);
        if (x != NULL)
            X509_CRL_free(x);
        goto done;
    }
    cf->dirid = id;
    // first verify the CRL
    sta = verify_crl(conp, x, cf->fields[CRF_FIELD_AKI],
                     cf->fields[CRF_FIELD_ISSUER], &chainOK);
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
        LOG(LOG_DEBUG, "CRL has %u entries", cf->snlen);
        uint8_t *u = (uint8_t *) cf->snlist;
        for (i = 0; i < cf->snlen; i++, u += SER_NUM_MAX_SZ)
        {
            if (LOG_DEBUG <= LOG_LEVEL)
            {
                char *x = hexify(SER_NUM_MAX_SZ, u, HEXIFY_X);
                LOG(LOG_DEBUG, "  entry %u: %s", i, x);
                free(x);
            }
            /** @bug ignores error code without explanation */
            revoke_cert_by_serial(scmp, conp, cf->fields[CRF_FIELD_ISSUER],
                                  cf->fields[CRF_FIELD_AKI], u);
        }
    }
    freecrf(cf);
    X509_CRL_free(x);

done:
    LOG(LOG_DEBUG, "add_crl() returning %s: %s",
        err2name(sta), err2string(sta));
    return (sta);
}

/**
 * @return
 *     On success, the size of the SKI in bytes.  On error, a negative
 *     error code (one of the ERR_SCM_* values).  The @c err_code type
 *     is not used as the return value type because the C standard
 *     allows enum types to be smaller than @c int (even though the
 *     enumeration constants themselves always have type @c int),
 *     which would limit the maximum supported size.
 */
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
    /** @bug should check to see if tmp is NULL */
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
            xsnprintf(str++, 2, ":");
        xsnprintf(str, 3, "%02X", tmp[i]);
        str += 2;
    }
    *str = 0;
    free(tmp);
    if (size < 0)
        /** @bug use a better error code */
        return ERR_SCM_UNSPECIFIED;
    return size;
}

/*
    Add (to the database) the EE cert embedded in *cmsp. The skip and
    certfilenamep parameters are output parameters.

    Returns:
    < 0: error (status code)
    0: successful, but EE cert in unknown state
    1: successful, and EE cert validated up through a trust anchor
*/
static err_code
extractAndAddCert(
    struct CMS *cmsp,
    scm *scmp,
    scmcon *conp,
    const char *outdir,
    int utrust,
    object_type typ,
    const char *outfile,
    char *skip,
    char *certfilenamep)
{
    LOG(LOG_DEBUG, "extractAndAddCert(cmsp=%p, scmp=%p, conp=%p"
        ", outdir=\"%s\", utrust=%d, typ=%d, outfile=\"%s\""
        ", skip=\"%s\", certfilenamep=%p)",
        cmsp, scmp, conp, outdir, utrust, typ, outfile, skip, certfilenamep);

    X509 *x509p = NULL;
    cert_fields *cf = NULL;
    unsigned int cert_id;
    char certname[PATH_MAX] = {'\0'};
    char pathname[PATH_MAX] = {'\0'};
    int hexify_sta;
    err_code sta = 0;
    struct Certificate *certp;
    certp = (struct Certificate *)member_casn(&cmsp->content.signedData.
                                              certificates.self, 0);
    if (!certp)
    {
        sta = ERR_SCM_BADNUMCERTS;
        goto done;
    }
    if ((certp->self.flags & ASN_INDEF_LTH_FLAG))
    {
        sta = ERR_SCM_ASN1_LTH;
        goto done;
    }
    // read the embedded cert information, in particular the ski
    if ((hexify_sta = hexify_ski(certp, skip)) < 0)
    {
        sta = hexify_sta;
        goto done;
    }
    // test for forbidden extension
    struct Extension *extp;
    for (extp =
         (struct Extension *)member_casn(&certp->toBeSigned.extensions.self,
                                         0);
         extp && diff_objid(&extp->extnID, id_extKeyUsage);
         extp = (struct Extension *)next_of(&extp->self));
    if (extp)
    {
        sta = ERR_SCM_BADEXT;
        goto done;
    }
    xsnprintf(certname, sizeof(certname), "%s.cer", outfile);
    // find or add the directory
    /** @bug ignores error code without explanation */
    const char *cc = retrieve_tdir(scmp, conp, &sta);
    const size_t pathname_lth = xsnprintf(pathname, sizeof(pathname),
                                          "%s/EEcertificates", cc);
    const size_t tdir_lth = pathname_lth - 15;
    free((void *)cc);
    struct stat statbuf;
    /** @bug ignores errno without explanation */
    if (stat(pathname, &statbuf))
        /** @bug ignores error code without explanation */
        mkdir(pathname, 0777);

    if (strncmp(outdir, pathname, tdir_lth)
        || ((outdir[tdir_lth] != '\0') && (outdir[tdir_lth] != '/')))
    {
        sta = ERR_SCM_WRITE_EE;
        goto done;
    }
    char *pathname_end = pathname + pathname_lth;
    size_t pathname_buf_remaining = sizeof(pathname) - pathname_lth;
    cc = &outdir[tdir_lth];
    while (cc)
    {
        char *d = strchr(cc, '/');
        char backup;
        if (d)
        {
            backup = *(++d);
            *d = '\0';
        }
        size_t len = xstrlcpy(pathname_end, cc, pathname_buf_remaining);
        pathname_end += len;
        pathname_buf_remaining -= len;
        if (d)
        {
            *d = backup;
        }
        cc = d;
        /** @bug ignores errno without explanation */
        if (stat(pathname, &statbuf) < 0)
            /** @bug ignores error code without explanation */
            mkdir(pathname, 0777);
    }

    unsigned int dir_id;
    /** @bug ignores error code without explanation */
    sta = findorcreatedir(scmp, conp, pathname, &dir_id);
    xsnprintf(pathname_end, pathname_buf_remaining, "/%s", certname);
    if (certfilenamep)
        /** @bug destination buffer might be too small */
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
        }
        else if (!sta && (cf->flags & SCM_FLAG_VALIDATED))
            sta = 1;
    }
    X509_free(x509p);
    freecf(cf);
    cf = NULL;
done:
    if (sta > 0) {
        LOG(LOG_DEBUG, "extractAndAddCert() returning %d", sta);
    }
    else
    {
        LOG(LOG_DEBUG, "extractAndAddCert() returning %s: %s",
            err2name(sta), err2string(sta));
    }
    return sta;
}

static err_code
add_roa_internal(
    scm *scmp,
    scmcon *conp,
    char *outfile,
    unsigned int dirid,
    char *ski,
    uint32_t asid,
    size_t prefixes_length,
    struct roa_prefix const *prefixes,
    char *sig,
    unsigned int flags)
{
    unsigned int roa_id = 0;
    char flagn[24];
    char asn[24];
    char lid[24];
    char did[24];
    err_code sta;

    // Buffer to hold a potentially large INSERT statement. This is
    // used to insert multiple rows per statement into
    // rpki_roa_prefix.
    size_t const multiinsert_len = 32 * 1024;
    char * multiinsert = malloc(multiinsert_len);
    if (multiinsert == NULL)
    {
        return ERR_SCM_NOMEM;
    }

    initTables(scmp);
    conp->mystat.tabname = "ROA";
    // first check for a duplicate signature
    sta = dupsigscm(scmp, conp, theROATable, sig);
    if (sta < 0)
    {
        free(multiinsert);
        return (sta);
    }
    sta = getmaxidscm(scmp, conp, "local_id", theROATable, &roa_id);
    if (sta < 0)
    {
        free(multiinsert);
        return (sta);
    }
    roa_id++;
    // fill in insertion structure
    xsnprintf(did, sizeof(did), "%u", dirid);
    xsnprintf(asn, sizeof(asn), "%" PRIu32, asid);
    xsnprintf(flagn, sizeof(flagn), "%u", flags);
    xsnprintf(lid, sizeof(lid), "%u", roa_id);
    scmkv cols[] = {
        {"filename", outfile},
        {"dir_id", did},
        {"ski", ski},
        {"sig", sig},
        {"asn", asn},
        {"flags", flagn},
        {"local_id", lid},
    };
    scmkva aone = {
        .vec = cols,
        .ntot = ELTS(cols),
        .nused = ELTS(cols),
        .vald = 0,
    };
    // add the ROA
    sta = insertscm(conp, theROATable, &aone);
    if (sta < 0)
    {
        free(multiinsert);
        return sta;
    }

    // Prefix for the insert statement that inserts multiple rows
    // into rpki_roa_prefix.
    static char const multiinsert_pre[] =
        "INSERT INTO rpki_roa_prefix "
        "(roa_local_id, prefix, prefix_length, prefix_max_length) "
        "VALUES ";
    static size_t const multiinsert_pre_len =
        sizeof(multiinsert_pre) - 1;

    // Index into multiinsert where the next character should be
    // written.
    size_t multiinsert_idx = 0;

    // String to represent a prefix as VARBINARY in SQL.
    char * prefix;

    int snprintf_ret;

    size_t i;
    for (i = 0; i < prefixes_length; ++i)
    {
        if (multiinsert_idx == 0)
        {
            memcpy(multiinsert, multiinsert_pre, multiinsert_pre_len);
            multiinsert_idx += multiinsert_pre_len;
        }

        prefix = hexify(
            prefixes[i].prefix_family_length, prefixes[i].prefix,
            HEXIFY_X);
        if (prefix == NULL)
        {
            sta = ERR_SCM_NOMEM;
            goto done;
        }

        snprintf_ret = snprintf(
            multiinsert + multiinsert_idx,
            multiinsert_len - multiinsert_idx,
            "(%u, %s, %" PRIu8 ", %" PRIu8 "),",
            roa_id,
            prefix,
            prefixes[i].prefix_length,
            prefixes[i].prefix_max_length);

        free(prefix);
        prefix = NULL;

        if (snprintf_ret < 0)
        {
            sta = ERR_SCM_INTERNAL;
            goto done;
        }
        else if ((size_t)snprintf_ret >=
            multiinsert_len - multiinsert_idx)
        {
            // The above write was truncated.

            if (multiinsert_idx == multiinsert_pre_len)
            {
                // The write was truncated even though it's the first
                // prefix in this statement. That's an internal error
                // because multiinsert_len is too small.
                sta = ERR_SCM_INTERNAL;
                goto done;
            }

            // Decrement i to ensure this prefix gets inserted
            // eventually.
            --i;

            // Overwrite the ',' from the previous prefix and
            // terminate the statement.
            --multiinsert_idx;
            multiinsert[multiinsert_idx] = '\0';
        }
        else if (i >= prefixes_length - 1)
        {
            // The write was not truncated, but this is the last
            // prefix, so overwrite the ',' from this prefix and
            // terminate the statement.
            multiinsert_idx += snprintf_ret - 1;
            multiinsert[multiinsert_idx] = '\0';
        }
        else
        {
            // The above write was not truncated and this is not the
            // last prefix, so attempt to add more prefixes before
            // executing the statement.
            multiinsert_idx += snprintf_ret;
            continue;
        }

        // Perform the insert.
        sta = statementscm_no_data(conp, multiinsert);
        if (sta < 0)
        {
            LOG(LOG_ERR,
                "Error inserting ROA prefixes. SQL query: %s",
                multiinsert);
            goto done;
        }

        // Start the statement at the beginning again with the next
        // prefix.
        multiinsert_idx = 0;
    }

done:

    if (sta < 0)
    {
        // There was an error, so delete the ROA we just inserted.
        err_code delete_status;

        delete_status = deletescm(conp, theROATable, &aone);
        if (delete_status < 0)
        {
            LOG(LOG_ERR,
                "Error deleting row from rpki_roa: %s (%d)",
                err2string(delete_status), delete_status);
        }

        // Then delete the prefixes, if they weren't already deleted
        // by the foreign key constraints.
        scmkv roa_prefixes_cols[1] = {
            {"roa_local_id", lid},
        };
        scmkva roa_prefixes_aone = {
            /** @bug shouldn't cols be roa_prefixes_cols? */
            .vec = cols,
            .ntot = ELTS(roa_prefixes_cols),
            .nused = ELTS(roa_prefixes_cols),
            .vald = 0,
        };
        delete_status =
            deletescm(conp, theROAPrefixTable, &roa_prefixes_aone);
        if (delete_status < 0)
        {
            LOG(LOG_ERR,
                "Error deleting from rpki_roa_prefix with "
                "roa_local_id %s: %s (%d)",
                lid, err2string(delete_status), delete_status);
        }
    }

    free(multiinsert);

    return (sta);
}

/*
 * Add a ROA to the DB.  This function returns 0 on success and a negative
 * error code on failure.
 */

err_code
add_roa(
    scm *scmp,
    scmcon *conp,
    char *outfile,
    char *outdir,
    char *outfull,
    unsigned int id,
    int utrust,
    object_type typ)
{
    struct CMS roa;             // note: roaFromFile constructs this
    char ski[60];
    char *sig = NULL;
    char certfilename[PATH_MAX];
    size_t prefixes_length = 0;
    struct roa_prefix *prefixes = NULL;
    unsigned char *bsig = NULL;
    err_code sta;
    int chainOK;
    int bsiglen = 0;
    int cert_added = 0;
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

    /**
     * @bug
     *     extractAndAddCert() returns 0 if things are sorta-OK
     *     and 1 if things are definitely OK.  If it's OK to treat
     *     these two cases identically then there should be an
     *     explanatory comment.
     */
    if ((sta = extractAndAddCert(&roa, scmp, conp, outdir,
                                 utrust, typ, outfile, ski,
                                 certfilename)) < 0)
        goto done;
    cert_added = 1;

    asid = roaAS_ID(&roa);  /* it's OK if this comes back zero */

    // signature NOTE: this does not calloc, only points
    if ((bsig = roaSignature(&roa, &bsiglen)) == NULL || bsiglen < 0)
    {
        sta = ERR_SCM_NOSIG;
        goto done;
    }

    if ((sig = hexify(bsiglen, bsig, HEXIFY_NO)) == NULL)
    {
        sta = ERR_SCM_NOMEM;
        goto done;
    }

    // verify the signature
    if ((sta = verify_roa(conp, &roa, ski, &chainOK)) != 0)
        goto done;

    // prefixes
    ssize_t prefixes_ret = roaGetPrefixes(&roa, &prefixes);
    if (prefixes_ret < 0)
    {
        /** @bug sta is still 0 here; is that intentional? */
        goto done;
    }
    prefixes_length = prefixes_ret;

    if ((sta = addStateToFlags(&flags, chainOK, outfile, outfull, scmp, conp)))
        goto done;

    // add to database
    if ((sta = add_roa_internal(scmp, conp, outfile, id, ski, asid,
                                prefixes_length, prefixes, sig, flags)))
        goto done;

done:
    // clean up
    free(prefixes);
    if (sta != 0 && cert_added)
        /** @bug ignores error code without explanation */
        (void)delete_object(scmp, conp, certfilename, outdir, outfull,
                            (unsigned int)0);
    delete_casn(&roa.self);
    if (sig != NULL)
        free(sig);
    return (sta);
}

err_code
add_manifest(
    scm *scmp,
    scmcon *conp,
    char *outfile,
    char *outdir,
    char *outfull,
    unsigned int id,
    int utrust,
    object_type typ)
{
    LOG(LOG_DEBUG, "add_manifest(scmp=%p, conp=%p, outfile=\"%s\""
        ", outdir=\"%s\", outfull=\"%s\", id=%u, utrust=%d, typ=%d)",
        scmp, conp, outfile, outdir, outfull, id, utrust, typ);

    err_code sta;
    int cert_added = 0;
    int stale;
    struct CMS cms;
    char *thisUpdate;
    char *nextUpdate;
    char certfilename[PATH_MAX];
    char asn_time[16];          // DER GenTime: strlen("YYYYMMDDhhmmssZ") ==
                                // 15
    unsigned int man_id = 0;

    CMS(&cms, 0);
    initTables(scmp);
    if (get_casn_file(&cms.self, outfull, 0) < 0)
    {
        LOG(LOG_ERR, "invalid manifest %s", outfull);
        delete_casn(&cms.self);
        sta = ERR_SCM_INVALASN;
        goto done;
    }
    if ((sta = manifestValidate(&cms, &stale)) < 0)
    {
        delete_casn(&cms.self);
        goto done;
    }
    // now, read the data out of the manifest structure
    struct Manifest *manifest =
        &cms.content.signedData.encapContentInfo.eContent.manifest;

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
        xsnprintf(manFiles + manFilesLen, MANFILES_SIZE - manFilesLen,
                  "%s%s", manFilesLen ? " " : "", file);
        if (manFilesLen)
            manFilesLen++;
        manFilesLen += strlen((char *)file);
    }
    err_code v = 0;
    char ski[60];
    do
    {                           // once through
        int read_len;
        // read this_upd and next_upd
        if (vsize_casn(&manifest->thisUpdate) + 1 > (int)sizeof(asn_time))
        {
            LOG(LOG_ERR, "thisUpdate is too large");
            sta = ERR_SCM_INVALDT;
            break;
        }
        read_len = read_casn(&manifest->thisUpdate, (unsigned char *)asn_time);
        if (read_len < 0)
        {
            LOG(LOG_ERR, "Could not read time for thisUpdate");
            sta = ERR_SCM_INVALDT;
            break;
        }
        else
        {
            asn_time[read_len] = '\0';
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
        read_len = read_casn(&manifest->nextUpdate, (unsigned char *)asn_time);
        if (read_len < 0)
        {
            LOG(LOG_ERR, "Could not read time for nextUpdate");
            sta = ERR_SCM_INVALDT;
            break;
        }
        else
        {
            asn_time[read_len] = '\0';
        }
        nextUpdate = ASNTimeToDBTime(asn_time, &sta, 1);
        if (sta < 0)
            break;

        if ((sta = extractAndAddCert(&cms, scmp, conp, outdir, utrust, typ,
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
            /** @bug ignores error code without explanation */
            (void)delete_object(scmp, conp, certfilename, outdir,
                                outfull, (unsigned int)0);
        delete_casn(&cms.self);
        goto done;
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
    char did[24];
    char mid[24];
    char lenbuf[20];
    xsnprintf(did, sizeof(did), "%u", id);
    char flagn[24];
    xsnprintf(flagn, sizeof(flagn), "%u", flags);
    xsnprintf(mid, sizeof(mid), "%u", man_id);
    xsnprintf(lenbuf, sizeof(lenbuf), "%u", manFilesLen);
    scmkv cols[] = {
        {"filename", outfile},
        {"dir_id", did},
        {"ski", ski},
        {"this_upd", thisUpdate},
        {"next_upd", nextUpdate},
        {"flags", flagn},
        {"local_id", mid},
        {"files", manFiles},
        {"fileslen", lenbuf},
    };
    scmkva aone = {
        .vec = cols,
        .ntot = ELTS(cols),
        .nused = ELTS(cols),
        .vald = 0,
    };
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
        /** @bug ignores error code without explanation */
        (void)delete_object(scmp, conp, certfilename,
                            outdir, outfull, (unsigned int)0);
    delete_casn(&(cms.self));
    free(thisUpdate);
    free(nextUpdate);
done:
    LOG(LOG_DEBUG, "add_manifest() returning %s: %s",
        err2name(sta), err2string(sta));
    return sta;
}

err_code
add_ghostbusters(
    scm *scmp,
    scmcon *conp,
    char *outfile,
    char *outdir,
    char *outfull,
    unsigned int id,
    int utrust,
    object_type typ)
{
    err_code sta;
    struct CMS cms;
    char ski[60];
    char certfilename[PATH_MAX]; // FIXME: this could allow a buffer overflow
    unsigned int local_id_old = 0;
    unsigned int local_id = 0;
    unsigned int flags = 0;

    CMS(&cms, 0);
    initTables(scmp);

    if (get_casn_file(&cms.self, outfull, 0) < 0)
    {
        LOG(LOG_ERR, "invalid ghostbusters %s", outfull);
        delete_casn(&cms.self);
        return ERR_SCM_INVALASN;
    }

    sta = ghostbustersValidate(&cms);
    if (sta < 0)
    {
        delete_casn(&cms.self);
        return sta;
    }

    sta = extractAndAddCert(&cms, scmp, conp, outdir, utrust, typ, outfile, ski,
                            certfilename);
    if (sta < 0)
    {
        delete_casn(&cms.self);
        return sta;
    }
    else if (sta == 0)
    {
        flags |= SCM_FLAG_NOCHAIN;
    }
    else
    {
        flags |= SCM_FLAG_VALIDATED;
    }

    sta = getmaxidscm(scmp, conp, "local_id", theGBRTable, &local_id_old);
    if (sta < 0)
    {
        /** @bug ignores error code without explanation */
        (void)delete_object(scmp, conp, certfilename, outdir, outfull, 0);
        delete_casn(&cms.self);
        return sta;
    }

    local_id = local_id_old + 1;
    if (local_id <= local_id_old)
    {
        // there was an integer overflow
        LOG(LOG_ERR,
            "There are too many ghostbusters records in the database.");
        /** @bug ignores error code without explanation */
        (void)delete_object(scmp, conp, certfilename, outdir, outfull, 0);
        delete_casn(&cms.self);
        return ERR_SCM_INTERNAL;
    }

    char dir_id_str[24];
    xsnprintf(dir_id_str, sizeof(dir_id_str), "%u", id);
    char local_id_str[24];
    xsnprintf(local_id_str, sizeof(local_id_str), "%u", local_id);
    char flags_str[24];
    xsnprintf(flags_str, sizeof(flags_str), "%u", flags);

    scmkv cols[] = {
        {"filename", outfile},
        {"dir_id", dir_id_str},
        {"local_id", local_id_str},
        {"ski", ski},
        {"flags", flags_str},
    };

    scmkva aone = {
        .vec = &cols[0],
        .ntot = ELTS(cols),
        .nused = ELTS(cols),
        .vald = 0,
    };

    sta = insertscm(conp, theGBRTable, &aone);
    if (sta < 0)
    {
        /** @bug ignores error code without explanation */
        (void)delete_object(scmp, conp, certfilename, outdir, outfull, 0);
        delete_casn(&cms.self);
        return sta;
    }

    delete_casn(&cms.self);
    return 0;
}

err_code
add_object(
    scm *scmp,
    scmcon *conp,
    char *outfile,
    char *outdir,
    char *outfull,
    int utrust)
{
    LOG(LOG_DEBUG, "add_object(scmp=%p, conp=%p, outfile=\"%s\""
        ", outdir=\"%s\", outfull=\"%s\", utrust=%d)",
        scmp, conp, outfile, outdir, outfull, utrust);

    unsigned int id = 0;
    unsigned int obj_id = 0;
    object_type typ;
    err_code sta;

    if (scmp == NULL || conp == NULL || conp->connected == 0 ||
        outfile == NULL || outdir == NULL || outfull == NULL)
    {
        sta = ERR_SCM_INVALARG;
        goto done;
    }
    // make sure it is really a file
    LOG(LOG_DEBUG, "calling isokfile(\"%s\")", outfull);
    sta = isokfile(outfull);
    LOG(LOG_DEBUG, "isokfile() returned %s: %s",
        err2name(sta), err2string(sta));
    if (sta < 0)
    {
        goto done;
    }
    // determine its filetype
    LOG(LOG_DEBUG, "calling infer_filetype(\"%s\")", outfull);
    typ = infer_filetype(outfull);
    LOG(LOG_DEBUG, "infer_filetype() returned %d", typ);
    // find or add the directory
    LOG(LOG_DEBUG, "calling findorcreatedir(%p, %p, \"%s\", %p)",
        scmp, conp, outdir, &id);
    sta = findorcreatedir(scmp, conp, outdir, &id);
    LOG(LOG_DEBUG, "findorcreatedir() returned %s: %s",
        err2name(sta), err2string(sta));
    if (sta < 0)
    {
        goto done;
    }
    // add the object based on the type
    switch (typ)
    {
    case OT_CER:
    case OT_CER_PEM:
    case OT_UNKNOWN:
    case OT_UNKNOWN + OT_PEM_OFFSET:
        LOG(LOG_DEBUG, "calling add_cert(%p, %p, \"%s\", \"%s\", %d, %d, %d, %p)",
            scmp, conp, outfile, outfull, id, utrust, typ, &obj_id);
        sta = add_cert(scmp, conp, outfile, outfull, id, utrust, typ, &obj_id);
        LOG(LOG_DEBUG, "add_cert() returned %s: %s",
            err2name(sta), err2string(sta));
        break;
    case OT_CRL:
    case OT_CRL_PEM:
        sta = add_crl(scmp, conp, outfile, outfull, id, utrust, typ);
        LOG(LOG_DEBUG, "add_crl() returned %s: %s",
            err2name(sta), err2string(sta));
        break;
    case OT_ROA:
    case OT_ROA_PEM:
        sta = add_roa(scmp, conp, outfile, outdir, outfull, id, utrust, typ);
        LOG(LOG_DEBUG, "add_roa() returned %s: %s",
            err2name(sta), err2string(sta));
        break;
    case OT_MAN:
    case OT_MAN_PEM:
        sta =
            add_manifest(scmp, conp, outfile, outdir, outfull, id, utrust,
                         typ);
        LOG(LOG_DEBUG, "add_manifest() returned %s: %s",
            err2name(sta), err2string(sta));
        break;
    case OT_GBR:
        sta = add_ghostbusters(scmp, conp, outfile, outdir, outfull, id,
                               utrust, typ);
        LOG(LOG_DEBUG, "add_ghostbusters() returned %s: %s",
            err2name(sta), err2string(sta));
        break;
    default:
        sta = ERR_SCM_INTERNAL;
        break;
    }
done:
    LOG(LOG_DEBUG, "add_object() returning %s: %s",
        err2name(sta), err2string(sta));
    return (sta);
}

/**
 * @brief
 *     internal iteration function used by iterate_crl() below
 *
 * This function processes CRLs one at a time.
 *
 * @return
 *     On failure it returns a negative error code.  On success it returns 0.
 */
static sqlvaluefunc crliterator;
err_code
crliterator(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
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
    err_code ista;
    int chgd = 0;
    err_code sta = 0;

    UNREFERENCED_PARAMETER(idx);
    if (conp == NULL || s == NULL || s->context == NULL)
        return (ERR_SCM_INVALARG);
    crlip = (crlinfo *)(s->context);
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
    if (snlen == 0 || s->vec[1].avalsize < (SQLLEN)(sizeof(unsigned int)))
        return (0);
    sninuse = *(unsigned int *)(s->vec[2].valptr);
    if (sninuse == 0 || s->vec[2].avalsize < (SQLLEN)(sizeof(unsigned int)))
        return (0);
    flags = *(unsigned int *)(s->vec[3].valptr);
    // ?????????? test for this in where of select statement ???????????????
    if ((flags & SCM_FLAG_VALIDATED) == 0 ||
        (flags & SCM_FLAG_NOCHAIN) != 0 ||
        s->vec[3].avalsize < (SQLLEN)(sizeof(unsigned int)))
        return (0);
    lid = *(unsigned int *)(s->vec[4].valptr);
    if (s->vec[5].avalsize <= 0)
        return (0);
    snlist = (uint8_t *)(s->vec[5].valptr);
    for (i = 0; i < snlen; i++)
    {
        ista =
            (*crlip->cfunc)(crlip->scmp, crlip->conp, issuer, aki,
                            &snlist[SER_NUM_MAX_SZ * i]);
        if (ista < 0)
            sta = ista;
        if (ista == 1)
        {
            // per STK action item #7 we no longer set SN to zero as an
            // exemplar
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
    if (sninuse > 0)
        sta = updateblobscm(conp, crlip->tabp, snlist, sninuse, snlen, lid);
    else
        sta = deletebylid(conp, crlip->tabp, lid);
    return (sta);
}

static uint8_t *snlist = NULL;

err_code
iterate_crl(
    scm *scmp,
    scmcon *conp,
    crlfunc *cfunc)
{
    unsigned int snlen = 0;
    unsigned int sninuse = 0;
    unsigned int flags = 0;
    unsigned int lid = 0;
    char issuer[512];
    char aki[512];
    err_code sta;

    // go for broke and allocate a blob large enough that it can hold
    // the entire snlist if necessary
    if (snlist == NULL)
        /** @bug magic number */
        snlist = malloc(16 * 1024 * 1024);
    if (snlist == NULL)
        return (ERR_SCM_NOMEM);
    memset(snlist, 0, 16 * 1024 * 1024);
    initTables(scmp);
    // set up a search for issuer, snlen, sninuse, flags, snlist and aki
    issuer[0] = 0;
    aki[0] = 0;
    scmsrch srch1[] = {
        {
            .colno = 1,
            .sqltype = SQL_C_CHAR,
            .colname = "issuer",
            .valptr = issuer,
            .valsize = 512,
            .avalsize = 0,
        },
        {
            .colno = 2,
            .sqltype = SQL_C_ULONG,
            .colname = "snlen",
            .valptr = &snlen,
            .valsize = sizeof(snlen),
            .avalsize = 0,
        },
        {
            .colno = 3,
            .sqltype = SQL_C_ULONG,
            .colname = "sninuse",
            .valptr = &sninuse,
            .valsize = sizeof(sninuse),
            .avalsize = 0,
        },
        {
            .colno = 4,
            .sqltype = SQL_C_ULONG,
            .colname = "flags",
            .valptr = &flags,
            .valsize = sizeof(flags),
            .avalsize = 0,
        },
        {
            .colno = 5,
            .sqltype = SQL_C_ULONG,
            .colname = "local_id",
            .valptr = &lid,
            .valsize = sizeof(lid),
            .avalsize = 0,
        },
        {
            .colno = 6,
            .sqltype = SQL_C_BINARY,
            .colname = "snlist",
            .valptr = snlist,
            .valsize = 16 * 1024 * 1024,
            .avalsize = 0,
        },
        {
            .colno = 7,
            .sqltype = SQL_C_CHAR,
            .colname = "aki",
            .valptr = aki,
            .valsize = 512,
            .avalsize = 0,
        },
    };
    scmsrcha srch = {
        .vec = srch1,
        .sname = NULL,
        .ntot = ELTS(srch1),
        .nused = ELTS(srch1),
        .vald = 0,
        .where = NULL,
        .wherestr = NULL,
    };
    crlinfo crli = {
        .scmp = scmp,
        .conp = conp,
        .tabp = theCRLTable,
        .cfunc = cfunc,
    };
    srch.context = &crli;
    sta = searchscm(conp, theCRLTable, &srch, NULL, &crliterator,
                    SCM_SRCH_DOVALUE_ALWAYS, NULL);
    return (sta);
}

/**
 * @brief
 *     Fill in the columns for a search with revoke_cert_and_children()
 *     as callback
 */
static void fillInColumns(
    scmsrch *srch1,
    unsigned int *lid,
    char *ski,
    char *subject,
    unsigned int *flags,
    scmsrcha *srch)
{
    scmsrch tmp[] = {
        {
            .sqltype = SQL_C_ULONG,
            .colname = "local_id",
            .valptr = lid,
            .valsize = sizeof(*lid),
        },
        {
            .sqltype = SQL_C_CHAR,
            .colname = "ski",
            .valptr = ski,
            /** @bug magic constant; should be SKISIZE? */
            .valsize = 512,
        },
        {
            .sqltype = SQL_C_CHAR,
            .colname = "subject",
            .valptr = subject,
            /** @bug magic constant; should be SUBJSIZE? */
            .valsize = 512,
        },
        {
            .sqltype = SQL_C_ULONG,
            .colname = "flags",
            .valptr = flags,
            .valsize = sizeof(*flags),
        },
    };
    for (size_t i = 0; i < ELTS(tmp); ++i)
    {
        tmp[i].colno = i + 1;
        tmp[i].avalsize = 0;
        srch1[i] = tmp[i];
    }
    *srch = (scmsrcha){
        .vec = srch1,
        .sname = NULL,
        .ntot = ELTS(tmp),
        .nused = ELTS(tmp),
        .vald = 0,
    };
}

err_code
revoke_cert_and_children(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    LOG(LOG_DEBUG, "revoke_cert_and_children(conp=%p, s=%p, idx=%zd)",
        conp, s, idx);

    unsigned int lid;
    err_code sta = 0;

    UNREFERENCED_PARAMETER(idx);
    lid = *(unsigned int *)(s->vec[0].valptr);
    if ((sta = deletebylid(conp, theCertTable, lid)) < 0)
    {
        goto done;
    }
    sta = verifyOrNotChildren(
        conp, s->vec[1].valptr, s->vec[2].valptr, NULL, NULL, lid, 0);

done:
    LOG(LOG_DEBUG, "add_cert() returning %s: %s",
        err2name(sta), err2string(sta));
    return sta;
}

err_code
delete_object(
    scm *scmp,
    scmcon *conp,
    char *outfile,
    char *outdir,
    char *outfull,
    unsigned int dir_id)
{
    unsigned int id;
    unsigned int lid;
    unsigned int flags;
    scmsrcha srch;
    scmsrch srch2[5];
    scmtab *thetab;
    object_type typ;
    err_code sta;
    char ski[512];
    char subject[512];
    char did[24];
    mcf mymcf;

    if (conp == NULL || conp->connected == 0 || outfile == NULL ||
        (outdir == NULL && !dir_id))
        return (ERR_SCM_INVALARG);
    // determine its filetype
    typ = infer_filetype(outfile);
    // find the directory
    if (scmp)
        initTables(scmp);       // may be null if tables have been initiated
    if (outdir)
    {
        scmkv one[] = {
            {"dirname", outdir},
        };
        scmkva where = {
            .vec = one,
            .ntot = ELTS(one),
            .nused = ELTS(one),
            .vald = 0,
        };
        scmsrch srch1[] = {
            {
                .colno = 1,
                .sqltype = SQL_C_ULONG,
                .colname = "dir_id",
                .valptr = &id,
                .valsize = sizeof(id),
                .avalsize = 0,
            },
        };
        srch = (scmsrcha){
            .vec = srch1,
            .sname = NULL,
            .ntot = ELTS(srch1),
            .nused = ELTS(srch1),
            .vald = 0,
            .where = &where,
            .wherestr = NULL,
        };
        sta =
            searchscm(conp, theDirTable, &srch, NULL, &ok,
                      SCM_SRCH_DOVALUE_ALWAYS, NULL);
        if (sta < 0)
            return (sta);
    }
    else
        id = dir_id;
    // fill in where structure
    xsnprintf(did, sizeof(did), "%u", id);
    scmkv dtwo[] = {
        {"filename", outfile},
        {"dir_id", did},
    };
    scmkva dwhere = {
        .vec = dtwo,
        .ntot = ELTS(dtwo),
        .nused = ELTS(dtwo),
        .vald = 0,
    };
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
        sta = searchscm(conp, thetab, &srch, NULL, &revoke_cert_and_children,
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
    case OT_GBR:
        thetab = theGBRTable;
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
        || typ == OT_MAN_PEM || typ == OT_GBR)
    {
        unsigned int ndir_id;
        char noutfile[PATH_MAX] = {'\0'};
        char noutdir[PATH_MAX] = {'\0'};
        char noutfull[PATH_MAX] = {'\0'};
        /** @bug ignores error code without explanation */
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

err_code
revoke_cert_by_serial(
    scm *scmp,
    scmcon *conp,
    char *issuer,
    char *aki,
    uint8_t *sn)
{
    LOG(LOG_DEBUG, "revoke_cert_by_serial(scmp=%p, conp=%p, issuer=\"%s\""
        ", aki=\"%s\", sn=%p)", scmp, conp, issuer, aki, sn);

    unsigned int lid;
    unsigned int flags;
    scmsrcha srch;
    /** @bug magic constant */
    scmsrch srch1[5];
    mcf mymcf;
    /** @bug magic constant */
    char ski[512];
    /** @bug magic constant */
    char subject[512];
    char *sno;
    uint8_t sn_zero[SER_NUM_MAX_SZ] = {0};
    err_code sta = 0;

    if (scmp == NULL || conp == NULL || conp->connected == 0)
    {
        sta = ERR_SCM_INVALARG;
        goto done;
    }
    if (issuer == NULL || issuer[0] == 0 || aki == NULL || aki[0] == 0 ||
        memcmp(sn, sn_zero, SER_NUM_MAX_SZ) == 0)
    {
        goto done;
    }
    initTables(scmp);
    mymcf.did = 0;
    mymcf.toplevel = 1;
    sno = hexify(SER_NUM_MAX_SZ, sn, HEXIFY_HAT);
    if (sno == NULL)
    {
        sta = ERR_SCM_NOMEM;
        goto done;
    }
    {
        char escaped [strlen(issuer)*2+1];
        mysql_escape_string(escaped, issuer, strlen(issuer));
        scmkv w[] = {
            {"issuer", escaped},
            {"sn", sno},
            {"aki", aki},
        };
        scmkva where = {
            .vec = w,
            .ntot = ELTS(w),
            .nused = ELTS(w),
            .vald = 0,
        };
        fillInColumns(srch1, &lid, ski, subject, &flags, &srch);
        srch.where = &where;
        srch.wherestr = NULL;
        srch.context = &mymcf;
        sta = searchscm(
            conp, theCertTable, &srch, NULL, &revoke_cert_and_children,
            SCM_SRCH_DOVALUE_ALWAYS, NULL);
    }
    free(sno);
    sno = NULL;
    if (sta >= 0)
    {
        sta = mymcf.did == 0 ? 0 : 1;
    }
done:
    if (sta > 0)
    {
        LOG(LOG_DEBUG, "revoke_cert_by_serial() returning %d", sta);
    }
    else
    {
        LOG(LOG_DEBUG, "revoke_cert_by_serial() returning %s: %s",
            err2name(sta), err2string(sta));
    }
    return sta;
}

err_code
deletebylid(
    scmcon *conp,
    scmtab *tabp,
    unsigned int lid)
{
    char mylid[24];
    int sta;

    if (conp == NULL || conp->connected == 0 || tabp == NULL)
        return (ERR_SCM_INVALARG);
    xsnprintf(mylid, sizeof(mylid), "%u", lid);
    scmkv where[] = {
        {"local_id", mylid},
    };
    scmkva lids = {
        .vec = where,
        .ntot = ELTS(where),
        .nused = ELTS(where),
        .vald = 0,
    };
    sta = deletescm(conp, tabp, &lids);
    return (sta);
}

/**
 * @brief
 *     callback for certificates that are may have been NOTYET but are
 *     now actually valid.  Mark them as such.
 */
static sqlvaluefunc certmaybeok;
err_code
certmaybeok(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    unsigned int pflags;
    char lid[24];
    err_code sta;

    UNREFERENCED_PARAMETER(idx);
    pflags = *(unsigned int *)(s->vec[3].valptr);
    // ????????? instead test for this in select statement ????????
    if ((pflags & SCM_FLAG_NOTYET) == 0)
        return (0);
    xsnprintf(lid, sizeof(lid), "%u",
              *(unsigned int *)(s->vec[0].valptr));
    scmkv one[] = {
        {"local_id", lid},
    };
    scmkva where = {
        .vec = one,
        .ntot = ELTS(one),
        .nused = ELTS(one),
        .vald = 0,
    };
    pflags &= ~SCM_FLAG_NOTYET;
    sta = setflagsscm(conp, theCertTable, &where, pflags);
    return (sta);
}

/**
 * @brief
 *     callback for certificates that are too new, e.g. not yet valid.
 *
 * Mark them as NOTYET in the flags field.
 */
static sqlvaluefunc certtoonew;
err_code
certtoonew(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    unsigned int pflags;
    char lid[24];
    err_code sta;

    UNREFERENCED_PARAMETER(idx);
    xsnprintf(lid, sizeof(lid), "%u",
              *(unsigned int *)(s->vec[0].valptr));
    scmkv one[] = {
        {"local_id", lid},
    };
    scmkva where = {
        .vec = one,
        .ntot = ELTS(one),
        .nused = ELTS(one),
        .vald = 0,
    };
    pflags = *(unsigned int *)(s->vec[3].valptr);
    pflags |= SCM_FLAG_NOTYET;
    sta = setflagsscm(conp, theCertTable, &where, pflags);
    return (sta);
}

/**
 * @brief
 *     This is the callback for certificates that are too old, e.g. no
 *     longer valid.
 *
 * Delete them (and their children) unless they have been reparented.
 */
static sqlvaluefunc certtooold;
err_code
certtooold(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx)
{
    char *ws;
    int tl;
    err_code sta;
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

err_code
certificate_validity(
    scm *scmp,
    scmcon *conp)
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
    err_code retsta = 0;
    err_code sta = 0;

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
    xsnprintf(vok, 48 + 2 * strlen(now),
              "valfrom <= \"%s\" AND \"%s\" <= valto", now, now);
    vf = (char *)calloc(24 + strlen(now), sizeof(char));
    if (vf == NULL)
        return (ERR_SCM_NOMEM);
    xsnprintf(vf, 24 + strlen(now), "\"%s\" < valfrom", now);
    vt = (char *)calloc(24 + strlen(now), sizeof(char));
    if (vt == NULL)
        return (ERR_SCM_NOMEM);
    xsnprintf(vt, 24 + strlen(now), "valto < \"%s\"", now);
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
                    &certmaybeok, SCM_SRCH_DOVALUE_ALWAYS, NULL);
    free((void *)vok);
    if (sta < 0 && sta != ERR_SCM_NODATA)
        retsta = sta;
    // search for certificates that are too new
    srch.wherestr = vf;
    // ?????????????? no need to call this here; instead ??????????
    // ?????????????? check when first put in ????????????
    sta = searchscm(conp, theCertTable, &srch, NULL,
                    &certtoonew, SCM_SRCH_DOVALUE_ALWAYS, NULL);
    free((void *)vf);
    if (sta < 0 && sta != ERR_SCM_NODATA && retsta == 0)
        retsta = sta;
    // search for certificates that are too old
    srch.wherestr = vt;
    sta = searchscm(conp, theCertTable, &srch, NULL,
                    &certtooold, SCM_SRCH_DOVALUE_ALWAYS, NULL);
    free((void *)vt);
    if (sta < 0 && sta != ERR_SCM_NODATA && retsta == 0)
        retsta = sta;
    return (retsta);
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
    xsnprintf(logName, 6 + strlen(appName), "RPKI %s", appName);
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
    if (invalidateCRLSrch != NULL)
    {
        freesrchscm(invalidateCRLSrch);
        invalidateCRLSrch = NULL;
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
