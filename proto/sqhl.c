/*
  $Id$
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <fam.h>
#include <ctype.h>
#include <syslog.h>

#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "diru.h"
#include "myssl.h"
#include "err.h"

#include "roa_utils.h"

/*
  Find a directory in the directory table, or create it if it is not found.
  Return the id in idp. The function returns 0 on success and a negative error
  code on failure.

  It is assumed that the existence of the putative directory has already been
  verified.
*/

int findorcreatedir(scm *scmp, scmcon *conp, char *dirname,
		    unsigned int *idp)
{
  scmsrcha *srch;
  scmkva    where;
  scmkva    ins;
  scmkv     two[2];
  scmtab   *tabp;
  int sta;

  if ( conp == NULL || conp->connected == 0 || dirname == NULL ||
       dirname[0] == 0 || idp == NULL )
    return(ERR_SCM_INVALARG);
  *idp = (unsigned int)(-1);
  conp->mystat.tabname = "DIRECTORY";
  tabp = findtablescm(scmp, "DIRECTORY");
  if ( tabp == NULL )
    return(ERR_SCM_NOSUCHTAB);
  two[0].column = "dir_id";
  two[0].value = NULL;
  two[1].column = "dirname";
  two[1].value = dirname;
  where.vec = &two[1];
  where.ntot = 1;
  where.nused = 1;
  ins.vec = &two[0];
  ins.ntot = 2;
  ins.nused = 2;
  srch = newsrchscm("focdir", 4, sizeof(unsigned int));
  if ( srch == NULL )
    return(ERR_SCM_NOMEM);
  sta = addcolsrchscm(srch, "dir_id", SQL_C_ULONG, sizeof(unsigned int));
  if ( sta < 0 )
    {
      freesrchscm(srch);
      return(sta);
    }
  srch->where = &where;
  sta = searchorcreatescm(scmp, conp, tabp, srch, &ins, idp);
  freesrchscm(srch);
  return(sta);
}

static int ok(scmcon *conp, scmsrcha *s, int idx)
{
  UNREFERENCED_PARAMETER(conp);
  UNREFERENCED_PARAMETER(s);
  UNREFERENCED_PARAMETER(idx);
  return(0);
}

/*
  Ask the DB about the top level repos directory. If found return a
  copy of the dirname. On error return NULL and set stap.
*/

char *retrieve_tdir(scm *scmp, scmcon *conp, int *stap)
{
  unsigned int blah;
  scmsrcha srch;
  scmsrch  srch1;
  scmkva   where;
  scmkv    one;
  scmtab *mtab;
  char   *oot;
  int     sta;

  if ( scmp == NULL || conp == NULL || conp->connected == 0 ||
       stap == NULL )
    return(NULL);
  conp->mystat.tabname = "METADATA";
  mtab = findtablescm(scmp, "METADATA");
  if ( mtab == NULL )
    {
      *stap = ERR_SCM_NOSUCHTAB;
      return(NULL);
    }
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
  if ( oot == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
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
  sta = searchscm(conp, mtab, &srch, NULL, ok, SCM_SRCH_DOVALUE_ALWAYS);
  if ( sta < 0 )
    {
      free((void *)oot);
      oot = NULL;
    }
  *stap = sta;
  return(oot);
}

/*
  Infer the object type based on which file extensions are present.
  The following can be present: .cer, .crl and .roa; .pem can also
  be present. If there is no suffix, then also check to see if the filename
  is of the form HHHHHHHH.N, where "HHHHHHHH" is eight hex digits, and .N
  is an integer suffix. In this case, it is a cert. If nothing can be
  determined then return unknown.

  On success this function returns one of the types defined in sqhl.h; on
  failure it returns a negative error code.
*/

int infer_filetype(char *fname)
{
  int pem = 0;
  int typ = 0;

  if ( fname == NULL || fname[0] == 0 )
    return(ERR_SCM_INVALARG);
  if ( strstr(fname, ".pem") != NULL )
    pem = 1;
  if ( strstr(fname, ".cer") != NULL )
    typ += OT_CER;
  if ( strstr(fname, ".crl") != NULL )
    typ += OT_CRL;
  if ( strstr(fname, ".roa") != NULL )
    typ += OT_ROA;
  if ( typ < OT_UNKNOWN || typ > OT_MAXBASIC )
    return(ERR_SCM_INVALFN);
  if ( pem > 0 )
    typ += OT_PEM_OFFSET;
  return(typ);
}

static char *certf[] =
  {
    "filename", "subject", "issuer", "sn", "valfrom", "valto",
    "ski", "aki", "sia", "aia", "crldp"
  } ;

// so don't have to pass scmp everywhere
static scmtab *theCertTable = NULL;

static int add_cert_internal(scm *scmp, scmcon *conp, cert_fields *cf,
			     unsigned int *cert_id)
{
  scmkva   aone;
  scmkv    cols[CF_NFIELDS+5];
  char *wptr = NULL;
  char *ptr;
  char  flagn[24];
  char  lid[24];
  char  did[24];
  char  blen[24];
  int   idx = 0;
  int   sta;
  int   i;

  sta = getmaxidscm(scmp, conp, "local_id", theCertTable, cert_id);
  if ( sta < 0 )
    return(sta);
  (*cert_id)++;
// fill in insertion structure
  for(i=0;i<CF_NFIELDS+3;i++)
    cols[i].value = NULL;
  for(i=0;i<CF_NFIELDS;i++)
    {
      if ( (ptr=cf->fields[i]) != NULL )
	{
	  cols[idx].column = certf[i];
	  cols[idx++].value = ptr;
	}
    }
  (void)sprintf(flagn, "%u", cf->flags);
  cols[idx].column = "flags";
  cols[idx++].value = flagn;
  (void)sprintf(lid, "%u", *cert_id);
  cols[idx].column = "local_id";
  cols[idx++].value = lid;
  (void)sprintf(did, "%u", cf->dirid);
  cols[idx].column = "dir_id";
  cols[idx++].value = did;
  if ( cf->ipblen > 0 )
    {
      cols[idx].column = "ipblen";
      (void)sprintf(blen, "%u", cf->ipblen); /* byte length */
      cols[idx++].value = blen;
      cols[idx].column = "ipb";
      wptr = hexify(cf->ipblen, cf->ipb);
      if ( wptr == NULL )
	return(ERR_SCM_NOMEM);
      cols[idx++].value = wptr;
    }
  aone.vec = &cols[0];
  aone.ntot = CF_NFIELDS+5;
  aone.nused = idx;
  aone.vald = 0;
  sta = insertscm(conp, theCertTable, &aone);
  if ( wptr != NULL )
    free((void *)wptr);
  return(sta);
}

static char *crlf[] =
  {
    "filename", "issuer", "last_upd", "next_upd", "crlno", "aki"
  } ;

static int add_crl_internal(scm *scmp, scmcon *conp, crl_fields *cf)
{
  unsigned int crl_id;
  scmtab  *ctab;
  scmkva   aone;
  scmkv    cols[CRF_NFIELDS+6];
  char *ptr;
  char *hexs;
  char  flagn[24];
  char  lid[24];
  char  did[24];
  char  csnlen[24];
  int   idx = 0;
  int   sta;
  int   i;

// the following statement could use a LOT of memory, so we try
// it first in case it fails
  hexs = hexify(cf->snlen*sizeof(long long), cf->snlist);
  if ( hexs == NULL )
    return(ERR_SCM_NOMEM);
  ctab = findtablescm(scmp, "CRL");
  if ( ctab == NULL )
    {
      free((void *)hexs);
      return(ERR_SCM_NOSUCHTAB);
    }
  conp->mystat.tabname = "CRL";
  sta = getmaxidscm(scmp, conp, "local_id", ctab, &crl_id);
  if ( sta < 0 )
    {
      free((void *)hexs);
      return(sta);
    }
  crl_id++;
// fill in insertion structure
  for(i=0;i<CRF_NFIELDS+6;i++)
    cols[i].value = NULL;
  for(i=0;i<CRF_NFIELDS;i++)
    {
      if ( (ptr=cf->fields[i]) != NULL )
	{
	  cols[idx].column = crlf[i];
	  cols[idx++].value = ptr;
	}
    }
  (void)sprintf(flagn, "%u", cf->flags);
  cols[idx].column = "flags";
  cols[idx++].value = flagn;
  (void)sprintf(lid, "%u", crl_id);
  cols[idx].column = "local_id";
  cols[idx++].value = lid;
  (void)sprintf(did, "%u", cf->dirid);
  cols[idx].column = "dir_id";
  cols[idx++].value = did;
  (void)sprintf(csnlen, "%d", cf->snlen);
  cols[idx].column = "snlen";
  cols[idx++].value = csnlen;
  cols[idx].column = "sninuse";
  cols[idx++].value = csnlen;
  cols[idx].column = "snlist";
  cols[idx++].value = hexs;
  aone.vec = &cols[0];
  aone.ntot = CRF_NFIELDS+6;
  aone.nused = idx;
  aone.vald = 0;
// add the CRL
  sta = insertscm(conp, ctab, &aone);
  free((void *)hexs);
  return(sta);
}

static int add_roa_internal(scm *scmp, scmcon *conp, char *outfile,
			    unsigned int dirid, char *ski, int asid)
{
  unsigned int roa_id;
  scmtab  *ctab;
  scmkva   aone;
  scmkv    cols[6];
  char  flagn[24];
  char  asn[24];
  char  lid[24];
  char  did[24];
  int   idx = 0;
  int   sta;

  ctab = findtablescm(scmp, "ROA");
  if ( ctab == NULL )
    return(ERR_SCM_NOSUCHTAB);
  conp->mystat.tabname = "ROA";
  sta = getmaxidscm(scmp, conp, "local_id", ctab, &roa_id);
  if ( sta < 0 )
    return(sta);
  roa_id++;
// fill in insertion structure
  cols[idx].column = "filename";
  cols[idx++].value = outfile;
  (void)sprintf(did, "%u", dirid);
  cols[idx].column = "dir_id";
  cols[idx++].value = did;
  cols[idx].column = "ski";
  cols[idx++].value = ski;
  (void)sprintf(asn, "%d", asid);
  cols[idx].column = "asn";
  cols[idx++].value = asn;
  (void)sprintf(flagn, "%u", SCM_FLAG_VALID);
  cols[idx].column = "flags";
  cols[idx++].value = flagn;
  (void)sprintf(lid, "%u", roa_id);
  cols[idx].column = "local_id";
  cols[idx++].value = lid;
  aone.vec = &cols[0];
  aone.ntot = 6;
  aone.nused = idx;
  aone.vald = 0;
// add the ROA
  sta = insertscm(conp, ctab, &aone);
  return(sta);
}

/*
  Callback function used in verification.
*/

static int cbx509err = 0;

static int verify_callback(int ok2, X509_STORE_CTX *store)
{
  if ( !ok2 )
    {
      cbx509err = store->error;
      (void)fprintf(stderr, "Error: %s\n",
		    X509_verify_cert_error_string(cbx509err));
    }
  else
    cbx509err = 0;
  return(ok2);
}

/******************************************************
 * static int checkit(cert_ctx, x, sk_untrusted,      *
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

static int checkit(X509_STORE *ctx, X509 *x, STACK_OF(X509) *uchain, 
                 STACK_OF(X509) *tchain, int purpose, ENGINE *e)
{
  X509_STORE_CTX *csc;
  int i;

  UNREFERENCED_PARAMETER(e);
  csc = X509_STORE_CTX_new();
  if ( csc == NULL )
    return(ERR_SCM_STORECTX);
  X509_STORE_set_flags(ctx, 0);
  if ( !X509_STORE_CTX_init(csc, ctx, x, uchain) )
    {
      X509_STORE_CTX_free(csc);
      return(ERR_SCM_STOREINIT);
    }
  if ( tchain != NULL )
    X509_STORE_CTX_trusted_stack(csc, tchain);
  if ( purpose >= 0 )
    X509_STORE_CTX_set_purpose(csc, purpose);
  i = X509_verify_cert(csc);
  X509_STORE_CTX_free(csc);
  if ( i )
    return(0);			/* verified ok */
  else
    return(ERR_SCM_NOTVALID);
}

/*
 * Read cert data from a file
 * Unlike cert2fields, this just fills in the X509 structure,
 *  not the certfields
 */
static X509 *readCertFromFile (char *ofullname, int *stap)
{
  X509  *px = NULL;
  BIO   *bcert = NULL;
  int   typ, x509sta;

// open the file
  typ = infer_filetype(ofullname);
  bcert = BIO_new(BIO_s_file());
  if ( bcert == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  x509sta = BIO_read_filename(bcert, ofullname);
  if ( x509sta <= 0 )
    {
      BIO_free_all(bcert);
      *stap = ERR_SCM_X509;
      return(NULL);
    }
// read the cert based on the input type
  if ( typ < OT_PEM_OFFSET )
    px = d2i_X509_bio(bcert, NULL);
  else
    px = PEM_read_bio_X509_AUX(bcert, NULL, NULL, NULL);
  BIO_free_all(bcert);
  if ( px == NULL )
    *stap = ERR_SCM_BADCERT;
  else
    *stap = 0;
  return(px);
}

/*
  Get the parent certificate by using the issuer and the aki of "x" to look
  it up in the db. If "x" has already been broken down in "cf" just
  use the issuer/aki from there, otherwise look it up from "x". The
  db lookup will return the filename and directory name of the
  parent cert, as well as its flags. Set those flags into "pflags"
*/

// static variables for efficiency, so only need to set up query once
static scmsrcha parentSrch;
static scmsrch  parentSrch1[3];
static char parentWhere[600];
static unsigned long parentBlah = 0;
static int parentNeedsInit = 1;
static char *parentDir;
static char *parentFile;

static X509 *parent_cert(scmcon *conp, X509 *x, cert_fields *cf,
			 int *stap, unsigned int *pflags)
{
  char *aki = NULL;
  char *issuer = NULL;
  char ofullname[PATH_MAX];		/* full pathname */
  int   alld = 0;
  int   x509sta = 0;

  if (parentNeedsInit) {
    parentNeedsInit = 0;
    parentSrch.sname = NULL;
    parentSrch.where = NULL;
    parentSrch.ntot = 3;
    parentSrch.nused = 0;
    parentSrch.context = &parentBlah;
    parentSrch.wherestr = parentWhere;
    parentSrch.vec = parentSrch1;
    addcolsrchscm (&parentSrch, "filename", SQL_C_CHAR, 256);
    addcolsrchscm (&parentSrch, "dirname", SQL_C_CHAR, 256);
    addcolsrchscm (&parentSrch, "flags", SQL_C_ULONG, sizeof (unsigned int));
    parentFile = (char *) parentSrch1[0].valptr;
    parentDir = (char *) parentSrch1[1].valptr;
  }

  *pflags = 0;
  *stap = 0;
  if ( cf == NULL )
    {
      cf = cert2fields(NULL, NULL, 0, &x, stap, &x509sta);
      if ( cf == NULL )
	return(NULL);
      alld++;
    }
  aki = cf->fields[CF_FIELD_AKI];
  issuer = cf->fields[CF_FIELD_ISSUER];
  if ( aki == NULL || issuer == NULL )
    {
      *stap = (aki == NULL) ? ERR_SCM_NOAKI : ERR_SCM_NOISSUER;
      if (alld > 0)
	freecf (cf);
      return(NULL);
    }
// find the entry whose subject is our issuer and whose ski is our aki,
// e.g. our parent
  sprintf (parentWhere, "ski=\"%s\" and subject=\"%s\" and (flags%%%d)>=%d",
	   aki, issuer, 2*SCM_FLAG_VALID, SCM_FLAG_VALID);
  if (alld > 0)
    freecf (cf);
  *stap = searchscm (conp, theCertTable, &parentSrch, NULL, ok,
		     SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN);
  if ( *stap < 0 ) return NULL;
  *pflags = *((unsigned int *) parentSrch1[2].valptr);
  (void)sprintf(ofullname, "%s/%s", parentDir, parentFile);
  return readCertFromFile (ofullname, stap);
}

// static variables for efficiency, so only need to set up query once
static scmsrcha revokedSrch;
static scmsrch  revokedSrch1[2];
static char revokedWhere[600];
static unsigned long revokedBlah = 0;
static int revokedNeedsInit = 1;
static scmtab *theCRLTable;
static unsigned long long *revokedSNList;
static unsigned int *revokedSNLen;
// static variables to pass to callback
static int isRevoked;
static unsigned long long revokedSN;

/* callback function for cert_revoked */
static int revokedHandler (scmcon *conp, scmsrcha *s, int numLine)
{
  conp = conp; numLine = numLine; s = s;  // silence compiler warnings
  unsigned int i;
  for (i = 0; i < *revokedSNLen; i++) {
    printf ("snlen = %d val = %llu\n", *revokedSNLen, revokedSNList[i]);
    if (revokedSNList[i] == revokedSN) {
      isRevoked = 1;
      break;
    }
  }
  return 0;
}

/*
 * Check whether a cert is revoked by a crl
 */
static int cert_revoked (scm *scmp, scmcon *conp, char *sn,
			 char *ski, char *subject)
{
  int sta;

  // set up query once first time through and then just modify
  if (revokedNeedsInit) {
    revokedNeedsInit = 0;
    theCRLTable = findtablescm (scmp, "CRL");
    revokedSrch.sname = NULL;
    revokedSrch.where = NULL;
    revokedSrch.ntot = 2;
    revokedSrch.nused = 0;
    revokedSrch.context = &revokedBlah;
    revokedSrch.wherestr = revokedWhere;
    revokedSrch.vec = revokedSrch1;
    addcolsrchscm (&revokedSrch, "snlen", SQL_C_ULONG, sizeof (unsigned int));
    addcolsrchscm (&revokedSrch, "snlist", SQL_C_BINARY, 16*1024*1024);
    revokedSNLen = (unsigned int *) revokedSrch1[0].valptr;
    revokedSNList = (unsigned long long *) revokedSrch1[1].valptr;
  }

  // query for crls such that aki = ski, issuer = issuer, and flags & valid
  // and set isRevoked = 1 if sn is in snlist
  sprintf (revokedWhere, "aki=\"%s\" and issuer=\"%s\" and (flags%%%d)>=%d",
	   ski, subject, 2*SCM_FLAG_VALID, SCM_FLAG_VALID);
  isRevoked = 0;
  revokedSN = strtoull (sn, NULL, 16);
  sta = searchscm (conp, theCRLTable, &revokedSrch, NULL, revokedHandler,
		   SCM_SRCH_DOVALUE_ALWAYS);
  if (sta == 0) {
    fprintf (stderr, "Error doing cert_revoked search\n");
  }
  return isRevoked;
}

/*
  Certificate verification code by mudge
*/

static int verify_cert(scmcon *conp, X509 *x, cert_fields *cf,
		       int *x509stap, int *chainOK)
{
  STACK_OF(X509) *sk_trusted = NULL;
  STACK_OF(X509) *sk_untrusted = NULL;
  X509_VERIFY_PARAM *vpm = NULL;
  X509_STORE *cert_ctx = NULL;
  X509_LOOKUP *lookup = NULL;
  X509_PURPOSE *xptmp = NULL;
  X509 *parent = NULL;
  unsigned int pflags;
  int purpose;
  int sta = 0;
  int i;

// create X509 store
  cert_ctx = X509_STORE_new();
  if ( cert_ctx == NULL )
    return(ERR_SCM_CERTCTX);
// set the verify callback
  X509_STORE_set_verify_cb_func(cert_ctx, verify_callback);
// initialize the purpose
  i = X509_PURPOSE_get_by_sname("any");
  xptmp = X509_PURPOSE_get0(i);
  purpose = X509_PURPOSE_get_id(xptmp);
// setup the verification parameters
  vpm = (X509_VERIFY_PARAM *)X509_VERIFY_PARAM_new();
  X509_VERIFY_PARAM_set_purpose(vpm, purpose);
  X509_STORE_set1_param(cert_ctx, vpm);
  lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
  X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
  lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
  X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
  ERR_clear_error();
// set up certificate stacks
  sk_trusted = sk_X509_new_null();
  if ( sk_trusted == NULL )
    {
      X509_STORE_free(cert_ctx);
      X509_VERIFY_PARAM_free(vpm);
      return(ERR_SCM_X509STACK);
    }
  sk_untrusted = sk_X509_new_null();
  if ( sk_untrusted == NULL )
    {
      sk_X509_free(sk_trusted);
      X509_STORE_free(cert_ctx);
      X509_VERIFY_PARAM_free(vpm);
      return(ERR_SCM_X509STACK);
    }
// if the certificate has already been flagged as trusted
// just push it on the trusted stack and verify it
  *chainOK = 0;
  if ( cf->flags & SCM_FLAG_TRUSTED ) {
    *chainOK = 1;
    sk_X509_push(sk_trusted, x);
  } else
    {
      pflags = 0;
      parent = parent_cert(conp, x, cf, &sta, &pflags);
      while ( parent != NULL )
	{
	  if ( pflags & SCM_FLAG_TRUSTED )
	    {
	      *chainOK = 1;
	      sk_X509_push(sk_trusted, parent);
	      break;
	    }
	  else
	    {
	      sk_X509_push(sk_untrusted, parent);
	      pflags = 0;
	      parent = parent_cert(conp, parent, NULL, &sta, &pflags);
	    }
	}
    }
  sta = 0;
  if (*chainOK)
    checkit(cert_ctx, x, sk_untrusted, sk_trusted, purpose, NULL);
  *x509stap = cbx509err;
  sk_X509_free(sk_untrusted);
  sk_X509_free(sk_trusted);
  X509_STORE_free(cert_ctx);
  X509_VERIFY_PARAM_free(vpm);
  return(sta);
}


// structure containing data of children to propagate
typedef struct _PropData {
  char *ski;
  char *subject;
  unsigned int flags;
  unsigned int id;
  char *filename;
  char *dirname;
} PropData;


/*
 * utility function for verify_children
 */
static int verifyChildCert (scmcon *conp, PropData *data)
{
  X509 *x = NULL;
  int   x509sta, sta, chainOK;
  char  pathname[PATH_MAX], *stmt;
  cert_fields *cf;

  sprintf (pathname, "%s/%s", data->dirname, data->filename);
  cf = cert2fields(data->filename, pathname, 0, &x, &sta, &x509sta);
  if ( x == NULL )
    return -100;
  sta = verify_cert (conp, x, cf, &x509sta, &chainOK);
  freecf (cf);
  if (sta != 0) {
    stmt = calloc (100, sizeof(char));
    sprintf (stmt, "delete from %s where local_id=%d;",
	     theCertTable->tabname, data->id);
    sta = statementscm (conp, stmt);
    free (stmt);
    return -100;
  } else if (data->flags | SCM_FLAG_NOCHAIN) {
    stmt = calloc (100, sizeof(char));
    sprintf (stmt, "update %s set flags=%d where local_id=%d;",
	     theCertTable->tabname,
	     (data->flags - SCM_FLAG_NOCHAIN) | SCM_FLAG_VALID, data->id);
    sta = statementscm (conp, stmt);
    free (stmt);
    return 0;
  }
  return -100;
}


// static variables for efficiency, so only need to set up query once
static scmsrcha childrenSrch;
static scmsrch  childrenSrch1[6];
static char childrenWhere[600];
static unsigned long childrenBlah = 0;
static int childrenNeedsInit = 1;
// static variables to pass back from callback and hold data
static int propListSize = 0;
static int propListMax = 200;
static PropData *propData = NULL;


/*
 * callback function for verify_children
 */
static int registerChild (scmcon *conp, scmsrcha *s, int idx)
{
  PropData *propData2;

  s = s; conp = conp; idx = idx;
  // push onto stack of children to propagate
  if (propListSize == propListMax) {
    propListMax *= 2;
    propData2 = (PropData *) calloc (propListMax, sizeof (PropData));
    memcpy (propData2, propData, propListSize * sizeof (PropData));
    free (propData);
    propData = propData2;
  }
  propData[propListSize].dirname = strdup (s->vec[0].valptr);
  propData[propListSize].filename = strdup (s->vec[1].valptr);
  propData[propListSize].flags = *((unsigned int *) (s->vec[2].valptr));
  propData[propListSize].ski = strdup (s->vec[3].valptr);
  propData[propListSize].subject = strdup (s->vec[4].valptr);
  propData[propListSize].id = *((unsigned int *) (s->vec[5].valptr));
  propListSize++;
  return 0;
}

/*
 * verify the children certs of the current cert
 */
static int verifyChildren (scmcon *conp, char *ski, char *subject)
{
  int isRoot = 1;
  int doIt, idx;

  // initialize query first time through
  if (childrenNeedsInit) {
    childrenNeedsInit = 0;
    childrenSrch.sname = NULL;
    childrenSrch.where = NULL;
    childrenSrch.ntot = 6;
    childrenSrch.nused = 0;
    childrenSrch.context = &childrenBlah;
    childrenSrch.wherestr = childrenWhere;
    childrenSrch.vec = childrenSrch1;
    addcolsrchscm (&childrenSrch, "dirname", SQL_C_CHAR, 4096);
    addcolsrchscm (&childrenSrch, "filename", SQL_C_CHAR, 256);
    addcolsrchscm (&childrenSrch, "flags", SQL_C_ULONG, sizeof(unsigned int));
    addcolsrchscm (&childrenSrch, "ski", SQL_C_CHAR, 128);
    addcolsrchscm (&childrenSrch, "subject", SQL_C_CHAR, 512);
    addcolsrchscm (&childrenSrch, "local_id", SQL_C_ULONG,
		   sizeof(unsigned int));
  }

  // iterate through all children, verifying
  if (propData == NULL)
    propData = (PropData *)calloc(propListMax, sizeof(PropData));
  propData[0].ski = ski;
  propData[0].subject = subject;
  propListSize = 1;
  while (propListSize > 0) {
    propListSize--;
    idx = propListSize;
    doIt = isRoot || (verifyChildCert (conp, &propData[idx]) == 0);
    if (doIt)
      sprintf(childrenWhere,
	  "aki=\"%s\" and ski<>\"%s\" and issuer=\"%s\" and (flags%%%d)>=%d",
	      propData[idx].ski, propData[idx].ski,
	      propData[idx].subject, 2*SCM_FLAG_NOCHAIN, SCM_FLAG_NOCHAIN);
    if (! isRoot) {
      free (propData[idx].filename);
      free (propData[idx].dirname);
      free (propData[idx].ski);
      free (propData[idx].subject);
    }
    if (doIt)
      searchscm (conp, theCertTable, &childrenSrch, NULL, registerChild,
		 SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN);
    // next verify crl children
    // ??????????
    //    if any child crl has flag changed to VALID, call doRevoke
    // ??????????
    // next verify roa children
    // ??????????
    isRoot = 0;
  }
  return 0;
}

/*
  Add a certificate to the DB. If utrust is set, check that it is
  self-signed first. Validate the cert and add it.

  This function returns 0 on success and a negative error code on
  failure.
*/

int add_cert(scm *scmp, scmcon *conp, char *outfile, char *outfull,
	     unsigned int id, int utrust, int typ, unsigned int *cert_id)
{
  cert_fields *cf;
  X509 *x = NULL;
  int   x509sta = 0;
  int   sta = 0;
  int   chainOK;

  if (theCertTable == NULL)
    theCertTable = findtablescm (scmp, "CERTIFICATE");
  cf = cert2fields(outfile, outfull, typ, &x, &sta, &x509sta);
  if ( cf == NULL || x == NULL )
    return(sta);
  cf->dirid = id;
  if ( utrust > 0 )
    {
      if (strcmp(cf->fields[CF_FIELD_SUBJECT],
		 cf->fields[CF_FIELD_ISSUER]) != 0) {
	freecf(cf);
	X509_free(x);
	return(ERR_SCM_NOTSS);
      }
      cf->flags |= SCM_FLAG_TRUSTED;
    }
// verify the cert
  sta = verify_cert(conp, x, cf, &x509sta, &chainOK);
  // check that no crls revoking this cert
  /*
   * ?????? uncomment this once other things working ???????
  if (sta == 0) {
    sta = cert_revoked (scmp, conp, cf->fields[CF_FIELD_SN],
			cf->fields[CF_FIELD_SKI],
			cf->fields[CF_FIELD_SUBJECT]);
  }
  */
// actually add the certificate
  if ( sta == 0 )
    {
      cf->flags |= (chainOK ? SCM_FLAG_VALID : SCM_FLAG_NOCHAIN);
      sta = add_cert_internal(scmp, conp, cf, cert_id);
    }
// try to validate children of cert
  if (sta == 0) {
    sta = verifyChildren (conp, cf->fields[CF_FIELD_SKI],
			  cf->fields[CF_FIELD_SUBJECT]);
  }
  freecf(cf);
  X509_free(x);
  return(sta);
}

/*
  Add a CRL to the DB.  This function returns 0 on success and a
  negative error code on failure.
*/

int add_crl(scm *scmp, scmcon *conp, char *outfile, char *outfull,
	    unsigned int id, int utrust, int typ)
{
  crl_fields *cf;
  X509_CRL   *x = NULL;
  int   crlsta = 0;
  int   sta = 0;

  UNREFERENCED_PARAMETER(utrust);
  cf = crl2fields(outfile, outfull, typ, &x, &sta, &crlsta);
  if ( cf == NULL || x == NULL )
    return(sta);
  cf->dirid = id;
// actually add the CRL
  cf->flags |= SCM_FLAG_VALID;
  sta = add_crl_internal(scmp, conp, cf);
  freecrf(cf);
  X509_CRL_free(x);
  return(sta);
}

/*
  Add a ROA to the DB.  This function returns 0 on success and a
  negative error code on failure.
*/

int add_roa(scm *scmp, scmcon *conp, char *outfile, char *outfull,
	    unsigned int id, int utrust, int typ)
{
  struct ROA *r = NULL;
  X509 *cert;
  char *ski;
  int   asid;
  int   sta;

  UNREFERENCED_PARAMETER(utrust);
  if ( scmp == NULL || conp == NULL || conp->connected == 0 || outfile == NULL ||
       outfile[0] == 0 || outfull == NULL || outfull[0] == 0 )
    return(ERR_SCM_INVALARG);
  sta = roaFromFile(outfull, typ >= OT_PEM_OFFSET ? FMT_PEM : FMT_DER, 1, &r);
  if ( sta < 0 )
    return(sta);
  ski = (char *)roaSKI(r);
  asid = roaAS_ID(r);
  if ( ski == NULL || ski[0] == 0 )
    {
      roaFree(r);
      return(ERR_SCM_INVALSKI);
    }
  if ( asid == 0 )
    {
      roaFree(r);
      return(ERR_SCM_INVALASID);
    }
  cert = (X509 *)roa_parent(scmp, conp, ski, &sta);
  if ( cert == NULL )
    {
      roaFree(r);
      return(sta);
    }
  sta = roaValidate2(r, cert);
  X509_free(cert);
  roaFree(r);
  if ( sta < 0 )
    return(sta);
  sta = add_roa_internal(scmp, conp, outfile, id, ski, asid);
  return(sta);
}

/*
  Add the indicated object to the DB. If "trusted" is set then verify
  that the object is self-signed. Note that this add operation may
  result in the directory also being added.

  Symlinks and files that are not regular files are not processed.

  This function returns 0 on success and a negative error code on
  failure.
*/

int add_object(scm *scmp, scmcon *conp, char *outfile, char *outdir,
	       char *outfull, int utrust)
{
  unsigned int id, obj_id;
  int typ;
  int sta;

  if ( scmp == NULL || conp == NULL || conp->connected == 0 ||
       outfile == NULL || outdir == NULL || outfull == NULL )
    return(ERR_SCM_INVALARG);
// make sure it is really a file
  sta = isokfile(outfull);
  if ( sta < 0 )
    return(sta);
// determine its filetype
  typ = infer_filetype(outfull);
  if ( typ < 0 )
    return(typ);
// find or add the directory
  sta = findorcreatedir(scmp, conp, outdir, &id);
  if ( sta < 0 )
    return(sta);
// add the object based on the type
  switch ( typ )
    {
    case OT_CER:
    case OT_CER_PEM:
    case OT_UNKNOWN:
    case OT_UNKNOWN+OT_PEM_OFFSET:
      sta = add_cert(scmp, conp, outfile, outfull, id, utrust, typ, &obj_id);
      break;
    case OT_CRL:
    case OT_CRL_PEM:
      sta = add_crl(scmp, conp, outfile, outfull, id, utrust, typ);
      break;
    case OT_ROA:
    case OT_ROA_PEM:
      sta = add_roa(scmp, conp, outfile, outfull, id, utrust, typ);
      break;
    default:
      sta = ERR_SCM_INTERNAL;
      break;
    }
  return(sta);
}

/*
  Delete an object. First find the object's directory. If it is not found
  then we are done. If it is found, then find the corresponding (filename, dir_id)
  combination in the appropriate table and issue the delete SQL call.
*/

int delete_object(scm *scmp, scmcon *conp, char *outfile, char *outdir,
		  char *outfull)
{
  unsigned int id;
  unsigned int blah;
  scmsrcha srch;
  scmsrch  srch1;
  scmkva   where;
  scmkva   dwhere;
  scmkv    one;
  scmkv    dtwo[2];
  scmtab  *thetab;
  char did[24];
  int  typ;
  int  sta;

  if ( scmp == NULL || conp == NULL || conp->connected == 0 ||
       outfile == NULL || outdir == NULL || outfull == NULL )
    return(ERR_SCM_INVALARG);
// determine its filetype
  typ = infer_filetype(outfull);
  if ( typ < 0 )
    return(typ);
// find the directory
  thetab = findtablescm(scmp, "DIRECTORY");
  if ( thetab == NULL )
    return(ERR_SCM_NOSUCHTAB);
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
  sta = searchscm(conp, thetab, &srch, NULL, ok, SCM_SRCH_DOVALUE_ALWAYS);
  if ( sta < 0 )
    return(sta);
// delete the object based on the type
// note that the directory itself is not deleted
  thetab = NULL;
  switch ( typ )
    {
    case OT_CER:
    case OT_CER_PEM:
    case OT_UNKNOWN:
    case OT_UNKNOWN+OT_PEM_OFFSET:
      thetab = findtablescm(scmp, "CERTIFICATE");
      break;
    case OT_CRL:
    case OT_CRL_PEM:
      thetab = findtablescm(scmp, "CRL");
      break;
    case OT_ROA:
    case OT_ROA_PEM:
      thetab = findtablescm(scmp, "ROA");
      break;
    default:
      sta = ERR_SCM_INTERNAL;
      break;
    }
  if ( thetab == NULL )
    sta = ERR_SCM_NOSUCHTAB;
  if ( sta < 0 )
    return(sta);
  dtwo[0].column = "filename";
  dtwo[0].value = outfile;
  dtwo[1].column = "dir_id";
  (void)sprintf(did, "%u", id);
  dtwo[1].value = did;
  dwhere.vec = &dtwo[0];
  dwhere.ntot = 2;
  dwhere.nused = 2;
  dwhere.vald = 0;
  sta = deletescm(conp, thetab, &dwhere);
  return(sta);
}

/*
  Get the flags value and possibly the local_id corresponding to a match
  on a search criterion.  Return the requested value(s) in the indicated
  pointers.

  This function returns 0 on success and a negative error code on failure.
*/

int getflagsidscm(scmcon *conp, scmtab *tabp, scmkva *where,
		  unsigned int *pflags, unsigned int *lidp)
{
  unsigned int blah;
  unsigned int flags;
  unsigned int lid;
  scmsrcha srch;
  scmsrch  srch1[2];
  int sta;

  if ( conp == NULL || conp->connected == 0 || tabp == NULL ||
       tabp->tabname == NULL || where == NULL )
    return(ERR_SCM_INVALARG);
  if ( pflags != NULL )
    *pflags = 0;
  if ( lidp != NULL )
    *lidp = 0;
  srch1[0].colno = 1;
  srch1[0].sqltype = SQL_C_ULONG;
  srch1[0].colname = "flags";
  srch1[0].valptr = (void *)&flags;
  srch1[0].valsize = sizeof(unsigned int);
  srch1[0].avalsize = 0;
  srch1[1].colno = 2;
  srch1[1].sqltype = SQL_C_ULONG;
  srch1[1].colname = "local_id";
  srch1[1].valptr = (void *)&lid;
  srch1[1].valsize = sizeof(unsigned int);
  srch1[1].avalsize = 0;
  srch.vec = &srch1[0];
  srch.sname = NULL;
  srch.ntot = 2;
  srch.nused = 2;
  srch.vald = 0;
  srch.where = where;
  srch.wherestr = NULL;
  srch.context = &blah;
  sta = searchscm(conp, tabp, &srch, NULL, ok, SCM_SRCH_DOVALUE_ALWAYS);
  if ( sta < 0 )
    return(sta);
  if ( pflags != NULL )
    *pflags = flags;
  if ( lidp != NULL )
    *lidp = lid;
  return(0);
}

/*
  This is the internal iteration function used by iterate_crl below.
  It processes CRLs one at a time.

  On failure it returns a negative error code. On success it returns 0.
*/

static int crliterator(scmcon *conp, scmsrcha *s, int idx)
{
  unsigned long long *snlist;
  unsigned int snlen;
  unsigned int sninuse;
  unsigned int flags;
  unsigned int lid;
  unsigned int i;
  crlinfo *crlip;
  char    *issuer;
  char    *aki;
  int      ista;
  int      chgd = 0;
  int      sta = 0;

  UNREFERENCED_PARAMETER(idx);
  if ( conp == NULL || s == NULL || s->context == NULL )
    return(ERR_SCM_INVALARG);
  crlip = (crlinfo *)(s->context);
  if ( crlip->conp != conp )
    return(ERR_SCM_INVALARG);
// if sninuse or snlen is 0 or if the flags mark the CRL as invalid, or
// if the issuer or aki is a null string, then ignore this CRL
  issuer = (char *)(s->vec[0].valptr);
  if ( issuer == NULL || issuer[0] == 0 || s->vec[0].avalsize == 0 )
    return(0);
  aki = (char *)(s->vec[6].valptr);
  if ( aki == NULL || aki[0] == 0 || s->vec[6].avalsize == 0 )
    return(0);
  snlen = *(unsigned int *)(s->vec[1].valptr);
  if ( snlen == 0 || s->vec[1].avalsize < (int)(sizeof(unsigned int)) )
    return(0);
  sninuse = *(unsigned int *)(s->vec[2].valptr);
  if ( sninuse == 0 || s->vec[2].avalsize < (int)(sizeof(unsigned int)) )
    return(0);
  flags = *(unsigned int *)(s->vec[3].valptr);
  if ( (flags & SCM_FLAG_VALID) == 0 ||
       s->vec[3].avalsize < (int)(sizeof(unsigned int)) )
    return(0);
  lid = *(unsigned int *)(s->vec[4].valptr);
  if ( s->vec[5].avalsize <= 0 )
    return(0);
  snlist = (unsigned long long *)(s->vec[5].valptr);
  for(i=0;i<snlen;i++)
    {
      ista = (*crlip->cfunc)(crlip->scmp, crlip->conp, issuer, aki, snlist[i]);
      if ( ista < 0 )
	sta = ista;
      if ( ista == 1 )
	{
// per STK action item #7 we no longer set SN to zero as an exemplar
//	  snlist[i] = 0;
	  chgd++;
	}
    }
// on error do nothing
  if ( sta < 0 )
    return(sta);
// no changes: do not update the CRL
  if ( chgd == 0 )
    return(0);
// update the sninuse and snlist values
// per STK action item #7 we are not zero-ing out snlist entries, so
// we never want to update sninuse
// sninuse -= chgd;
  if ( sninuse > 0 )
    sta = updateblobscm(conp, crlip->tabp, snlist, sninuse, snlen, lid);
  else
    sta = deletebylid(conp, crlip->tabp, lid);
  return(sta);
}

/*
  Iterate through all CRLs in the DB, recursively processing each
  CRL to obtain its (issuer, snlist) information. For each SN in
  the list, call a specified function (persumably a certificate
  revocation function) on that (issuer, sn) combination.

  On success this function returns 0.  On failure it returns a negative
  error code.
*/

int iterate_crl(scm *scmp, scmcon *conp, crlfunc cfunc)
{
  unsigned int snlen = 0;
  unsigned int sninuse = 0;
  unsigned int flags = 0;
  unsigned int lid = 0;
  scmsrcha srch;
  scmsrch  srch1[7];
  scmtab  *tabp;
  crlinfo  crli;
  char     issuer[512];
  char     aki[512];
  void    *snlist;
  int      sta;

// go for broke and allocate a blob large enough that it can hold
// the entire snlist if necessary
  snlist = (void *)calloc(16*1024*1024/sizeof(unsigned long long),
			  sizeof(unsigned long long));
  if ( snlist == NULL )
    return(ERR_SCM_NOMEM);
  tabp = findtablescm(scmp, "CRL");
  if ( tabp == NULL )
    {
      free(snlist);
      return(ERR_SCM_NOSUCHTAB);
    }
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
  srch1[5].valsize = 16*1024*1024;
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
  crli.tabp = tabp;
  crli.cfunc = cfunc;
  srch.context = (void *)&crli;
  sta = searchscm(conp, tabp, &srch, NULL, crliterator, SCM_SRCH_DOVALUE_ALWAYS);
  free(snlist);
  return(sta);
}

typedef struct _mcf
{
  scmtab *ctab;
  scmtab *rtab;
  int     did;
  int     toplevel;
} mcf;

static int rparents(scmcon *conp, scmsrcha *s, int idx)
{
  unsigned int flags;
  mcf *mymcf;

  UNREFERENCED_PARAMETER(conp);
  UNREFERENCED_PARAMETER(idx);
  mymcf = (mcf *)(s->context);
  flags = *(unsigned int *)(s->vec->valptr);
  if ( (flags & SCM_FLAG_VALID) != 0 && (flags & SCM_FLAG_CA) == 0 )
    mymcf->did++;
  return(0);
}

/*
  This function returns the number of valid certificates that
  have and ski=SK and do not have the CA bit set, or a negative error
  code on failure.
*/

static int countvalidroaparents(scmcon *conp, scmsrcha *s, char *SK)
{
  unsigned int flags = 0;
  scmsrcha srch;
  scmsrch  srch1;
  scmkva   where;
  scmkv    w;
  mcf     *mymcf;
  int      cnt2;
  int      cnt;
  int      sta;

  mymcf = (mcf *)(s->context);
  w.column = "ski";
  w.value = SK;
  where.vec = &w;
  where.ntot = 1;
  where.nused = 1;
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
  cnt = mymcf->did;
  mymcf->did = 0;
  srch.context = (void *)mymcf;
  sta = searchscm(conp, mymcf->ctab, &srch, NULL, rparents,
		  SCM_SRCH_DOVALUE_ALWAYS);
  if ( sta < 0 )
    return(sta);
  cnt2 = mymcf->did;
  mymcf->did = cnt;
  return(cnt2);
}

/*
  Revoke a ROA. Check to see if it has been reparented first, however.
*/

static int revoke_roa(scmcon *conp, scmsrcha *s, int idx)
{
  unsigned int lid;
  mcf   *mcfp;
  char   ski[512];
  int    sta;

  UNREFERENCED_PARAMETER(idx);
  mcfp = (mcf *)(s->context);
  lid = *(unsigned int *)(s->vec[0].valptr);
  (void)strcpy(ski, (char *)(s->vec[1].valptr));
  if ( countvalidroaparents(conp, s, ski) > 0 )
    return(0);
  sta = deletebylid(conp, mcfp->rtab, lid);
  if ( sta == 0 )
    mcfp->did++;
  return(sta);
}

static int cparents(scmcon *conp, scmsrcha *s, int idx)
{
  unsigned int flags;
  mcf *mymcf;

  UNREFERENCED_PARAMETER(conp);
  UNREFERENCED_PARAMETER(idx);
  mymcf = (mcf *)(s->context);
  flags = *(unsigned int *)(s->vec->valptr);
  if ( (flags & SCM_FLAG_VALID) != 0 )
    mymcf->did++;
  return(0);
}

/*
  This function returns the number of valid certificates that
  have subject=IS and ski=AK, or a negative error code on failure.
*/

static int countvalidparents(scmcon *conp, scmsrcha *s, char *IS, char *AK)
{
  unsigned int flags = 0;
  scmsrcha srch;
  scmsrch  srch1;
  scmkva   where;
  scmkv    w[2];
  mcf     *mymcf;
  char     ws[256];
  char    *now;
  int      cnt2;
  int      cnt;
  int      sta;

  mymcf = (mcf *)(s->context);
  w[0].column = "subject";
  w[0].value = IS;
  w[1].column = "ski";
  w[1].value = AK;
  where.vec = &w[0];
  where.ntot = 2;
  where.nused = 2;
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
  if ( now == NULL )
    return(sta);
  (void)sprintf(ws, "valfrom < \"%s\" AND \"%s\" < valto", now, now);
  free((void *)now);
  srch.wherestr = &ws[0];
  cnt = mymcf->did;
  mymcf->did = 0;
  srch.context = (void *)mymcf;
  sta = searchscm(conp, mymcf->ctab, &srch, NULL, cparents,
		  SCM_SRCH_DOVALUE_ALWAYS);
  if ( sta < 0 )
    return(sta);
  cnt2 = mymcf->did;
  mymcf->did = cnt;
  return(cnt2);
}

/*
  This is the model revocation function for certificates. It handles
  the case where a certificate is expired or revoked. Given that this
  function can be called recursively it must be careful in what it does.
  If the top level certificate it is handed has either the EXPIRED or
  REVOKED bit set in its flags field, or the toplevel flag in the search
  context, then it is deleted. If none of these bits it set then it checks
  to see if it has been reparented. If it has not been reparented, it is deleted,
  otherwise the function just returns.

  If a certificate is deleted, then this function is invoked recursively
  to check to see if any of its children (certificate children or ROA
  children) also need to be deleted.
*/

static int revoke_cert_and_children(scmcon *conp, scmsrcha *s, int idx)
{
  unsigned int lid;
  scmkva  cwhere;
  scmkva *ow;
  scmkv   cone;
  mcf    *mcfp;
  char    s1[256];
  char    a1[512];
  char    is[512];
  int     dodel = 0;
  int     sta;

  UNREFERENCED_PARAMETER(idx);
  mcfp = (mcf *)(s->context);
// if the cert has flags marked for deletion, or if this is a toplevel
// invocation, then actually delete the cert
  if ( mcfp->toplevel > 0 )
    {
      dodel = 1;
      mcfp->toplevel = 0;
    }
// if the cert has not otherwise been marked for deletion, but has not
// been reparented, then actually delete the cert, otherwise just return
  if ( dodel == 0 )
    {
      (void)strcpy(is, (char *)(s->vec[3].valptr));
      (void)strcpy(a1, (char *)(s->vec[4].valptr));
      if ( countvalidparents(conp, s, is, a1) > 0 )
	return(0);
      dodel = 1;
    }
  lid = *(unsigned int *)(s->vec[0].valptr);
  (void)strcpy(s1, (char *)(s->vec[1].valptr));
  sta = deletebylid(conp, mcfp->ctab, lid);
  if ( sta < 0 )
    return(sta);
  mcfp->did++;
// next, revoke all certificate children of this certificate
  cone.column = "aki";
  cone.value = s1;
  cwhere.vec = &cone;
  cwhere.ntot = 1;
  cwhere.nused = 1;
  cwhere.vald = 0;
  ow = s->where;
  s->where = &cwhere;
//  (void)printf("Searching for certs with aki=%s\n", s1);
  sta = searchscm(conp, mcfp->ctab, s, NULL, revoke_cert_and_children,
		  SCM_SRCH_DOVALUE_ALWAYS);
  if ( sta == ERR_SCM_NODATA )
    sta = 0;			/* ok if no such children */
  if ( sta < 0 )
    {
      s->where = ow;
      return(sta);
    }
// finally, revoke all ROA children of this certificate
  cone.column = "ski";
//  (void)printf("Searching for ROAs with ski=%s\n", s->where->vec[0].value);
  sta = searchscm(conp, mcfp->rtab, s, NULL, revoke_roa,
		  SCM_SRCH_DOVALUE_ALWAYS);
  s->where = ow;
  if ( sta == ERR_SCM_NODATA )
    sta = 0;
  return(sta);
}

/*
  This is the model callback function for iterate_crl. For each
  (issuer, sn) pair with sn != 0 it attempts to find a certificate
  with those values in the DB. If found, it then attempts to delete
  the certificate and all its children. Note that in deleting an EE
  certificate, some of its children may be ROAs, so this table has
  to be searched as well.

  This function returns 1 if it deleted something, 0 if it deleted
  nothing and a negative error code on failure.
*/

int model_cfunc(scm *scmp, scmcon *conp, char *issuer, char *aki,
		unsigned long long sn)
{
  unsigned int pflags;
  unsigned int lid;
  scmsrcha srch;
  scmsrch  srch1[5];
  scmkva   where;
  scmkv    w[3];
  mcf      mymcf;
  char     ski[512];
  char     laki[512];
  char     is[512];
  char     sno[24];
  int      sta;

  if ( scmp == NULL || conp == NULL || conp->connected == 0 )
    return(ERR_SCM_INVALARG);
  if ( issuer == NULL || issuer[0] == 0 || aki == NULL || aki[0] == 0 ||
       sn == 0 )
    return(0);
  mymcf.ctab = findtablescm(scmp, "CERTIFICATE");
  if ( mymcf.ctab == NULL )
    return(ERR_SCM_NOSUCHTAB);
  mymcf.rtab = findtablescm(scmp, "ROA");
  if ( mymcf.rtab == NULL )
    return(ERR_SCM_NOSUCHTAB);
  mymcf.did = 0;
  mymcf.toplevel = 1;
  w[0].column = "issuer";
  w[0].value = issuer;
  (void)sprintf(sno, "%lld", sn);
  w[1].column = "sn";
  w[1].value = &sno[0];
  w[2].column = "ski";
  w[2].value = aki;
  where.vec = &w[0];
  where.ntot = 3;
  where.nused = 3;
  where.vald = 0;
  srch1[0].colno = 1;
  srch1[0].sqltype = SQL_C_ULONG;
  srch1[0].colname = "local_id";
  srch1[0].valptr = (void *)&lid;
  srch1[0].valsize = sizeof(unsigned int);
  srch1[0].avalsize = 0;
  srch1[1].colno = 2;
  srch1[1].sqltype = SQL_C_CHAR;
  srch1[1].colname = "ski";
  srch1[1].valptr = &ski[0];
  srch1[1].valsize = 512;
  srch1[1].avalsize = 0;
  // ?????????? no longer need flags ???????????? GAGNON
  srch1[2].colno = 3;
  srch1[2].sqltype = SQL_C_ULONG;
  srch1[2].valptr = (void *)&pflags;
  srch1[2].valsize = sizeof(unsigned int);
  srch1[2].avalsize = 0;
  srch1[3].colno = 4;
  srch1[3].sqltype = SQL_C_CHAR;
  srch1[3].colname = "issuer";
  srch1[3].valptr = &is[0];
  srch1[3].valsize = 512;
  srch1[3].avalsize = 0;
  srch1[4].colno = 5;
  srch1[4].sqltype = SQL_C_CHAR;
  srch1[4].colname = "aki";
  srch1[4].valptr = &laki[0];
  srch1[4].valsize = 512;
  srch1[4].avalsize = 0;
  srch.vec = &srch1[0];
  srch.sname = NULL;
  srch.ntot = 5;
  srch.nused = 5;
  srch.vald = 0;
  srch.where = &where;
  srch.wherestr = NULL;
  srch.context = &mymcf;
  sta = searchscm(conp, mymcf.ctab, &srch, NULL, revoke_cert_and_children,
		  SCM_SRCH_DOVALUE_ALWAYS);
  if ( sta < 0 )
    return(sta);
  else
    return(mymcf.did == 0 ? 0 : 1);
}

/*
  Delete a particular local_id from a table.
*/

int deletebylid(scmcon *conp, scmtab *tabp, unsigned int lid)
{
  scmkva  lids;
  scmkv   where;
  char    mylid[24];
  int     sta;

  if ( conp == NULL || conp->connected == 0 || tabp == NULL )
    return(ERR_SCM_INVALARG);
  where.column = "local_id";
  (void)sprintf(mylid, "%u", lid);
  where.value = mylid;
  lids.vec = &where;
  lids.ntot = 1;
  lids.nused = 1;
  lids.vald = 0;
  sta = deletescm(conp, tabp, &lids);
  return(sta);
}

/*
  This is the callback for certificates that are may have been NOTYET
  but are now actually valid. Mark them as such.
*/

static int certmaybeok(scmcon *conp, scmsrcha *s, int idx)
{
  unsigned int pflags;
  scmkva   where;
  scmkv    one;
  char lid[24];
  int  sta;

  UNREFERENCED_PARAMETER(idx);
  pflags = *(unsigned int *)(s->vec[2].valptr);
  // ????????? instead test for this in select statement ???????? GAGNON
  if ( (pflags & SCM_FLAG_NOTYET) == 0 )
    return(0);
  (void)sprintf(lid, "%u", *(unsigned int *)(s->vec[0].valptr));
  one.column = "local_id";
  one.value = &lid[0];
  where.vec = &one;
  where.ntot = 1;
  where.nused = 1;
  where.vald = 0;
  pflags &= ~SCM_FLAG_NOTYET;
  pflags |= SCM_FLAG_VALID;
  sta = setflagsscm(conp, ((mcf *)(s->context))->ctab, &where, pflags);
  return(sta);
}

/*
  This is the callback for certificates that are too new, e.g. not
  yet valid. Mark them as NOTYET in the flags field.
*/

static int certtoonew(scmcon *conp, scmsrcha *s, int idx)
{
  unsigned int pflags;
  scmkva   where;
  scmkv    one;
  char lid[24];
  int  sta;

  UNREFERENCED_PARAMETER(idx);
  (void)sprintf(lid, "%u", *(unsigned int *)(s->vec[0].valptr));
  one.column = "local_id";
  one.value = &lid[0];
  where.vec = &one;
  where.ntot = 1;
  where.nused = 1;
  where.vald = 0;
  pflags = *(unsigned int *)(s->vec[2].valptr);
  pflags &= ~SCM_FLAG_VALID;
  pflags |= SCM_FLAG_NOTYET;
  sta = setflagsscm(conp, ((mcf *)(s->context))->ctab, &where, pflags);
  return(sta);
}

/*
  This is the callback for certificates that are too old, e.g. no longer
  valid. Delete them (and their children) unless they have been reparented.
*/

static int certtooold(scmcon *conp, scmsrcha *s, int idx)
{
  char *ws;
  int   tl;
  int   sta;
  mcf  *mymcf;

  ws = s->wherestr;
  s->wherestr = NULL;
  mymcf = (mcf *)(s->context);
  tl = mymcf->toplevel;
  mymcf->toplevel = 1;
  sta = revoke_cert_and_children(conp, s, idx);
  s->wherestr = ws;
  mymcf->toplevel = tl;
  return(sta);
}

/*
  This function sweeps through all certificates. If it finds any that are
  valid but marked as NOTYET, it clears the NOTYET bit and sets the VALID
  bit. If it finds any where the start validity date (valfrom) is in the future,
  it marks them as NOTYET. If it finds any where the end validity date (valto)
  is in the past, it deletes them.
*/

int certificate_validity(scm *scmp, scmcon *conp)
{
  unsigned int pflags;
  unsigned int lid;
  scmsrcha srch;
  scmsrch  srch1[5];
  scmtab  *ctab;
  scmtab  *rtab;
  mcf   mymcf;
  char  skistr[512];
  char  akistr[512];
  char  issstr[512];
  char *vok;
  char *vf;
  char *vt;
  char *now;
  int   retsta = 0;
  int   sta = 0;

  if ( scmp == NULL || conp == NULL || conp->connected == 0 )
    return(ERR_SCM_INVALARG);
  ctab = findtablescm(scmp, "CERTIFICATE");
  if ( ctab == NULL )
    return(ERR_SCM_NOSUCHTAB);
  rtab = findtablescm(scmp, "ROA");
  if ( rtab == NULL )
    return(ERR_SCM_NOSUCHTAB);
  mymcf.ctab = ctab;
  mymcf.rtab = rtab;
  mymcf.did = 0;
  mymcf.toplevel = 0;
  now = LocalTimeToDBTime(&sta);
  if ( now == NULL )
    return(sta);
// construct the validity clauses
  vok = (char *)calloc(48+2*strlen(now), sizeof(char));
  if ( vok == NULL )
    return(ERR_SCM_NOMEM);
  (void)sprintf(vok, "valfrom <= \"%s\" AND \"%s\" <= valto", now, now);
  vf = (char *)calloc(24+strlen(now), sizeof(char));
  if ( vf == NULL )
    return(ERR_SCM_NOMEM);
  (void)sprintf(vf, "\"%s\" < valfrom", now);
  vt = (char *)calloc(24+strlen(now), sizeof(char));
  if ( vt == NULL )
    return(ERR_SCM_NOMEM);
  (void)sprintf(vt, "valto < \"%s\"", now);
  free((void *)now);
// search for certificates that might now be valid
// in order to use revoke_cert_and_children the first five
// columns of the search must be the lid, ski, flags, issuer and aki
  srch1[0].colno = 1;
  srch1[0].sqltype = SQL_C_ULONG;
  srch1[0].colname = "local_id";
  srch1[0].valptr = (void *)&lid;
  srch1[0].valsize = sizeof(unsigned int);
  srch1[0].avalsize = 0;
  srch1[1].colno = 2;
  srch1[1].sqltype = SQL_C_CHAR;
  srch1[1].colname = "ski";
  srch1[1].valptr = skistr;
  srch1[1].valsize = 512;
  srch1[1].avalsize = 0;
  srch1[2].colno = 3;
  srch1[2].sqltype = SQL_C_ULONG;
  srch1[2].colname = "flags";
  srch1[2].valptr = (void *)&pflags;
  srch1[2].valsize = sizeof(unsigned int);
  srch1[2].avalsize = 0;
  srch1[3].colno = 4;
  srch1[3].sqltype = SQL_C_CHAR;
  srch1[3].colname = "issuer";
  srch1[3].valptr = issstr;
  srch1[3].valsize = 512;
  srch1[3].avalsize = 0;
  srch1[4].colno = 5;
  srch1[4].sqltype = SQL_C_CHAR;
  srch1[4].colname = "aki";
  srch1[4].valptr = akistr;
  srch1[4].valsize = 512;
  srch1[4].avalsize = 0;
  srch.vec = (&srch1[0]);
  srch.sname = NULL;
  srch.ntot = 5;
  srch.nused = 5;
  srch.vald = 0;
  srch.where = NULL;
  srch.wherestr = vok;
  srch.context = (void *)&mymcf;
  sta = searchscm(conp, ctab, &srch, NULL, certmaybeok, SCM_SRCH_DOVALUE_ALWAYS);
  free((void *)vok);
  if ( sta < 0 && sta != ERR_SCM_NODATA )
    retsta = sta;
// search for certificates that are too new
  srch.wherestr = vf;
  // ?????????????? no need to call this here; instead ??????????
  // ?????????????? check when first put in ???????????? GAGNON
  sta = searchscm(conp, ctab, &srch, NULL, certtoonew, SCM_SRCH_DOVALUE_ALWAYS);
  free((void *)vf);
  if ( sta < 0 && sta != ERR_SCM_NODATA && retsta == 0 )
    retsta = sta;
// search for certificates that are too old
  srch.wherestr = vt;
  sta = searchscm(conp, ctab, &srch, NULL, certtooold, SCM_SRCH_DOVALUE_ALWAYS);
  free((void *)vt);
  if ( sta < 0 && sta != ERR_SCM_NODATA && retsta == 0 )
    retsta = sta;
  return(retsta);
}

/*
  Update the metadata table to indicate when a particular client ran last.
*/

int ranlast(scm *scmp, scmcon *conp, char *whichcli)
{
  scmtab *mtab;
  char   *now;
  char    what;
  int     sta = 0;

  if ( scmp == NULL || conp == NULL || conp->connected == 0 ||
       whichcli == NULL || whichcli[0] == 0 )
    return(ERR_SCM_INVALARG);
  what = toupper(whichcli[0]);
  if ( what != 'R' && what != 'Q' && what != 'C' && what != 'G' )
    return(ERR_SCM_INVALARG);
  mtab = findtablescm(scmp, "METADATA");
  if ( mtab == NULL )
    return(ERR_SCM_NOSUCHTAB);
  conp->mystat.tabname = "METADATA";
  now = LocalTimeToDBTime(&sta);
  if ( now == NULL )
    return(sta);
  sta = updateranlastscm(conp, mtab, what, now);
  free((void *)now);
  return(sta);
}

/*
  Given the SKI of a ROA, this function returns the X509 * structure
  for the corresponding EE certificate (or NULL on error).
*/

void *roa_parent(scm *scmp, scmcon *conp, char *ski, int *stap)
{
  unsigned long blah = 0;
  unsigned long dblah = 0;
  unsigned long pflags = 0;
  unsigned int  dirid = 0;
  scmsrcha srch;
  scmsrch  srch1[3];
  scmsrcha dsrch;
  scmsrch  dsrch1;
  scmkva   where;
  scmkv    one;
  scmkva   dwhere;
  scmkv    done;
  scmtab  *tabp;
  X509    *px = NULL;
  BIO     *bcert = NULL;
  char     cdirid[24];
  char    *ofullname;
  char    *ofile;
  char    *dfile;
  int      x509sta = 0;
  int      typ;

  if ( stap == NULL )
    return(NULL);
  if ( scmp == NULL || conp == NULL || conp->connected == 0 ||
       ski == NULL || ski[0] == 0 )
    {
      *stap = ERR_SCM_INVALARG;
      return(NULL);
    }
  tabp = findtablescm(scmp, "CERTIFICATE");
  if ( tabp == NULL )
    {
      *stap = ERR_SCM_NOSUCHTAB;
      return(NULL);
    }
  conp->mystat.tabname = "CERTIFICATE";
  ofile = (char *)calloc(PATH_MAX+1, sizeof(char));
  if ( ofile == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
// find the certificate with the given SKI
  one.column = "ski";
  one.value = ski;
  where.vec = &one;
  where.ntot = 1;
  where.nused = 1;
  where.vald = 0;
  srch1[0].colno = 1;
  srch1[0].sqltype = SQL_C_CHAR;
  srch1[0].colname = "filename";
  srch1[0].valptr = (void *)ofile;
  srch1[0].valsize = PATH_MAX;
  srch1[0].avalsize = 0;
  srch1[1].colno = 2;
  srch1[1].sqltype = SQL_C_ULONG;
  srch1[1].colname = "dir_id";
  srch1[1].valptr = (void *)&dirid;
  srch1[1].valsize = sizeof(unsigned int);
  srch1[1].avalsize = 0;
  srch1[2].colno = 3;
  srch1[2].sqltype = SQL_C_ULONG;
  srch1[2].colname = "flags";
  srch1[2].valptr = (void *)&pflags;
  srch1[2].valsize = sizeof(unsigned int);
  srch1[2].avalsize = 0;
  srch.vec = (&srch1[0]);
  srch.sname = NULL;
  srch.ntot = 3;
  srch.nused = 3;
  srch.vald = 0;
  srch.where = &where;
  srch.wherestr = NULL;
  srch.context = &blah;
  *stap = searchscm(conp, tabp, &srch, NULL, ok, SCM_SRCH_DOVALUE_ALWAYS);
  if ( *stap < 0 )
    {
      free((void *)ofile);
      return(NULL);
    }
// the flags field must be marked valid, and must not have the CA bit set
  if ( (pflags & SCM_FLAG_VALID) == 0 )
    {
      free((void *)ofile);
      *stap = ERR_SCM_NOTVALID;
      return(NULL);
    }
  if ( (pflags & SCM_FLAG_CA) != 0 )
    {
      free((void *)ofile);
      *stap = ERR_SCM_NOTEE;
      return(NULL);
    }
// now find the directory name from the id
  tabp = findtablescm(scmp, "DIRECTORY");
  if ( tabp == NULL )
    {
      free((void *)ofile);
      *stap = ERR_SCM_NOSUCHTAB;
      return(NULL);
    }
  dfile = (char *)calloc(PATH_MAX+1, sizeof(char));
  if ( dfile == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  done.column = "dir_id";
  (void)sprintf(cdirid, "%u", dirid);
  done.value = (&cdirid[0]);
  dwhere.vec = &done;
  dwhere.ntot = 1;
  dwhere.nused = 1;
  dwhere.vald = 0;
  dsrch1.colno = 1;
  dsrch1.sqltype = SQL_C_CHAR;
  dsrch1.valptr = (void *)dfile;
  dsrch1.colname = "dirname";
  dsrch1.valsize = PATH_MAX;
  dsrch1.avalsize = 0;
  dsrch.vec = &dsrch1;
  dsrch.sname = NULL;
  dsrch.ntot = 1;
  dsrch.nused = 1;
  dsrch.vald = 0;
  dsrch.where = &dwhere;
  dsrch.wherestr = NULL;
  dsrch.context = &dblah;
  *stap = searchscm(conp, tabp, &dsrch, NULL, ok, SCM_SRCH_DOVALUE_ALWAYS);
  if ( *stap < 0 )
    {
      free((void *)dfile);
      free((void *)ofile);
      return(NULL);
    }
  ofullname = (char *)calloc(PATH_MAX+1, sizeof(char));
  if ( ofullname == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  (void)sprintf(ofullname, "%s/%s", dfile, ofile);
  free((void *)dfile);
  free((void *)ofile);
  typ = infer_filetype(ofullname);
  bcert = BIO_new(BIO_s_file());
  if ( bcert == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  x509sta = BIO_read_filename(bcert, ofullname);
  if ( x509sta <= 0 )
    {
      BIO_free_all(bcert);
      free((void *)ofullname);
      *stap = ERR_SCM_X509;
      return(NULL);
    }
// read the cert based on the input type
  if ( typ < OT_PEM_OFFSET )
    px = d2i_X509_bio(bcert, NULL);
  else
    px = PEM_read_bio_X509_AUX(bcert, NULL, NULL, NULL);
  BIO_free_all(bcert);
  if ( px == NULL )
    *stap = ERR_SCM_BADCERT;
  else
    *stap = 0;
  free((void *)ofullname);
  return((void *)px);
}


/*
 * open syslog and write message that application started
 */

void startSyslog(char *appName)
{
  char *logName = (char *) calloc (6 + strlen (appName), sizeof (char));
  sprintf (logName, "APKI %s", appName);
  openlog (logName, LOG_PID, 0);
  syslog (LOG_NOTICE, "Application Started");
}

/*
 * close syslog and write message that application ended
 */
void stopSyslog(void)
{
  syslog (LOG_NOTICE, "Application Ended");
  closelog();
}
