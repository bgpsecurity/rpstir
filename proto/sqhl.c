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
 * static variables that hold tables and function to initialize them
 */
static scmtab *theCertTable = NULL;
static scmtab *theROATable = NULL;
static scmtab *theCRLTable = NULL;
static scmtab *theDirTable = NULL;
static scmtab *theMetaTable = NULL;
static scm    *theSCMP = NULL;

static void initTables (scm *scmp)
{
  if (theCertTable == NULL) {
    theDirTable = findtablescm(scmp, "DIRECTORY");
    if (theDirTable == NULL) {
      fprintf (stderr, "Error finding directory table\n");
      exit (-1);
    }
    theMetaTable = findtablescm(scmp, "METADATA");
    if (theMetaTable == NULL) {
      fprintf (stderr, "Error finding metadata table\n");
      exit (-1);
    }
    theCertTable = findtablescm (scmp, "CERTIFICATE");
    if (theCertTable == NULL) {
      fprintf (stderr, "Error finding certificate table\n");
      exit (-1);
    }
    theCRLTable = findtablescm (scmp, "CRL");
    if (theCRLTable == NULL) {
      fprintf (stderr, "Error finding crl table\n");
      exit (-1);
    }
    theROATable = findtablescm (scmp, "ROA");
    if (theROATable == NULL) {
      fprintf (stderr, "Error finding roa table\n");
      exit (-1);
    }
    theSCMP = scmp;
  }
}

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
  int sta;

  if ( conp == NULL || conp->connected == 0 || dirname == NULL ||
       dirname[0] == 0 || idp == NULL )
    return(ERR_SCM_INVALARG);
  *idp = (unsigned int)(-1);
  conp->mystat.tabname = "DIRECTORY";
  initTables (scmp);
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
  sta = searchorcreatescm(scmp, conp, theDirTable, srch, &ins, idp);
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
  char   *oot;
  int     sta;

  if ( scmp == NULL || conp == NULL || conp->connected == 0 ||
       stap == NULL )
    return(NULL);
  conp->mystat.tabname = "METADATA";
  initTables (scmp);
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
  sta = searchscm(conp, theMetaTable, &srch, NULL,
		  ok, SCM_SRCH_DOVALUE_ALWAYS);
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

  initTables (scmp);
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
  initTables (scmp);
  conp->mystat.tabname = "CRL";
  sta = getmaxidscm(scmp, conp, "local_id", theCRLTable, &crl_id);
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
  sta = insertscm(conp, theCRLTable, &aone);
  free((void *)hexs);
  return(sta);
}

static int add_roa_internal(scm *scmp, scmcon *conp, char *outfile,
			    unsigned int dirid, char *ski, int asid,
			    int isValid)
{
  unsigned int roa_id;
  scmkva   aone;
  scmkv    cols[6];
  char  flagn[24];
  char  asn[24];
  char  lid[24];
  char  did[24];
  int   idx = 0;
  int   sta;

  conp->mystat.tabname = "ROA";
  sta = getmaxidscm(scmp, conp, "local_id", theROATable, &roa_id);
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
  (void)sprintf(flagn, "%u", isValid ? SCM_FLAG_VALID : SCM_FLAG_NOCHAIN);
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
  sta = insertscm(conp, theROATable, &aone);
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
static scmsrch  parentSrch1[5];
static char parentWhere[600];
static unsigned long parentBlah = 0;
static int parentNeedsInit = 1;
static char *parentDir, *parentFile;
static unsigned int *parentFlags;
static char *parentAKI, *parentIssuer;

static X509 *parent_cert(scmcon *conp, char *ski, char *subject,
			 int *stap, char **pathname)
{
  char ofullname[PATH_MAX];		/* full pathname */

  if (parentNeedsInit) {
    parentNeedsInit = 0;
    parentSrch.sname = NULL;
    parentSrch.where = NULL;
    parentSrch.ntot = 5;
    parentSrch.nused = 0;
    parentSrch.context = &parentBlah;
    parentSrch.wherestr = parentWhere;
    parentSrch.vec = parentSrch1;
    addcolsrchscm (&parentSrch, "filename", SQL_C_CHAR, 256);
    addcolsrchscm (&parentSrch, "dirname", SQL_C_CHAR, 256);
    addcolsrchscm (&parentSrch, "flags", SQL_C_ULONG, sizeof (unsigned int));
    addcolsrchscm (&parentSrch, "aki", SQL_C_CHAR, 128);
    addcolsrchscm (&parentSrch, "issuer", SQL_C_CHAR, 512);
    parentFile = (char *) parentSrch1[0].valptr;
    parentDir = (char *) parentSrch1[1].valptr;
    parentFlags = (unsigned int *) parentSrch1[2].valptr;
    parentAKI = (char *) parentSrch1[3].valptr;
    parentIssuer = (char *) parentSrch1[4].valptr;
  }

  *stap = 0;
// find the entry whose subject is our issuer and whose ski is our aki,
// e.g. our parent
  if (subject != NULL)
    sprintf (parentWhere, "ski=\"%s\" and subject=\"%s\" and (flags%%%d)>=%d",
	     ski, subject, 2*SCM_FLAG_VALID, SCM_FLAG_VALID);
  else
    sprintf (parentWhere, "ski=\"%s\" and (flags%%%d)>=%d",
	     ski, 2*SCM_FLAG_VALID, SCM_FLAG_VALID);
  *stap = searchscm (conp, theCertTable, &parentSrch, NULL, ok,
		     SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN);
  if ( *stap < 0 ) return NULL;
  (void)sprintf(ofullname, "%s/%s", parentDir, parentFile);
  if (pathname != NULL)
    strcpy (*pathname, ofullname);
  return readCertFromFile (ofullname, stap);
}

// static variables for efficiency, so only need to set up query once
static scmsrcha revokedSrch;
static scmsrch  revokedSrch1[2];
static char revokedWhere[600];
static unsigned long revokedBlah = 0;
static int revokedNeedsInit = 1;
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
static int cert_revoked (scm *scmp, scmcon *conp, char *sn, char *issuer)
{
  int sta;

  // set up query once first time through and then just modify
  if (revokedNeedsInit) {
    revokedNeedsInit = 0;
    initTables (scmp);
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

  // query for crls such that issuer = issuer, and flags & valid
  // and set isRevoked = 1 if sn is in snlist
  sprintf (revokedWhere, "issuer=\"%s\" and (flags%%%d)>=%d",
	   issuer, 2*SCM_FLAG_VALID, SCM_FLAG_VALID);
  isRevoked = 0;
  revokedSN = strtoull (sn, NULL, 10);
  sta = searchscm (conp, theCRLTable, &revokedSrch, NULL, revokedHandler,
		   SCM_SRCH_DOVALUE_ALWAYS);
  return isRevoked;
}

/*
  Certificate verification code by mudge
*/

static int verify_cert(scmcon *conp, X509 *x, int isTrusted, char *parentSKI,
		      char *parentSubject, int *x509stap, int *chainOK)
{
  STACK_OF(X509) *sk_trusted = NULL;
  STACK_OF(X509) *sk_untrusted = NULL;
  X509_VERIFY_PARAM *vpm = NULL;
  X509_STORE *cert_ctx = NULL;
  X509_LOOKUP *lookup = NULL;
  X509_PURPOSE *xptmp = NULL;
  X509 *parent = NULL;
  int purpose, i;
  int sta = 0;

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
  if ( isTrusted ) {
    *chainOK = 1;
    sk_X509_push(sk_trusted, x);
  } else
    {
      parent = parent_cert(conp, parentSKI, parentSubject, &sta, NULL);
      while ( parent != NULL )
	{
	  if ( (*parentFlags) & SCM_FLAG_TRUSTED )
	    {
	      *chainOK = 1;
	      sk_X509_push(sk_trusted, parent);
	      break;
	    }
	  else
	    {
	      sk_X509_push(sk_untrusted, parent);
	      parent = parent_cert(conp, parentAKI, parentIssuer, &sta, NULL);
	    }
	}
    }
  sta = 0;
  if (*chainOK)
    sta = checkit(cert_ctx, x, sk_untrusted, sk_trusted, purpose, NULL);
  *x509stap = cbx509err;
  sk_X509_pop_free(sk_untrusted, X509_free);
  sk_X509_pop_free(sk_trusted, X509_free);
  X509_STORE_free(cert_ctx);
  X509_VERIFY_PARAM_free(vpm);
  return(sta);
}


/*
 * crl verification code
 */
static int verify_crl (scmcon *conp, X509_CRL *x, char *parentSKI,
		       char *parentSubject, int *x509sta, int *chainOK)
{
  int sta = 0;
  X509 *parent;
  EVP_PKEY *pkey;

  parent = parent_cert (conp, parentSKI, parentSubject, x509sta, NULL);
  if (parent == NULL) {
    *chainOK = 0;
    return 0;
  }
  *chainOK = 1;
  pkey = X509_get_pubkey (parent);
  sta = X509_CRL_verify (x, pkey);
  return (sta <= 0) ? ERR_SCM_NOTVALID : 0;
}


/*
 * roa utility
 */
static unsigned char *readfile(char *fn, int *stap)
{
  struct stat mystat;
  char *ptr;
  int   fd;
  int   rd;

  if ( stap == NULL )
    return(NULL);
  if ( fn == NULL || fn[0] == 0 )
    {
      *stap = ERR_SCM_INVALARG;
      return(NULL);
    }
  fd = open(fn, O_RDONLY);
  if ( fd < 0 )
    {
      *stap = ERR_SCM_COFILE;
      return(NULL);
    }
  memset(&mystat, 0, sizeof(mystat));
  if ( fstat(fd, &mystat) < 0 || mystat.st_size == 0 )
    {
      (void)close(fd);
      *stap = ERR_SCM_COFILE;
      return(NULL);
    }
  ptr = (char *)calloc(mystat.st_size, sizeof(char));
  if ( ptr == NULL )
    {
      (void)close(fd);
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  rd = read(fd, ptr, mystat.st_size);
  (void)close(fd);
  if ( rd != mystat.st_size )
    {
      free((void *)ptr);
      ptr = NULL;
      *stap = ERR_SCM_COFILE;
    }
  else
    *stap = 0;
  return((unsigned char *)ptr);
}

/*
 * roa verification code
 */
static int verify_roa (scmcon *conp, struct ROA *r, char *ski, int *chainOK)
{
  X509 *cert;
  int sta;
  char fn[PATH_MAX], *fn2;
  unsigned char *blob = NULL;

  fn2 = fn;
  cert = parent_cert (conp, ski, NULL, &sta, &fn2);
  if ( cert == NULL ) {
    *chainOK = 0;
    return 0;
  }
  *chainOK = 1;
// read the ASN.1 blob from the file
  blob = readfile(fn, &sta);
  if ( blob != NULL )
    {
      sta = roaValidate2(r, cert, blob);
      free((void *)blob);
    }
  X509_free(cert);
  return (sta < 0) ? ERR_SCM_NOTVALID : 0;
}


/* utility function */
static int updateValidFlags (scmcon *conp, scmtab *tabp, unsigned int id,
			     unsigned int prevFlags, int isValid)
{
  char stmt[100];
  int flags = isValid ?
    ((prevFlags - SCM_FLAG_NOCHAIN) | SCM_FLAG_VALID) :
    ((prevFlags - SCM_FLAG_VALID) | SCM_FLAG_NOCHAIN);
  sprintf (stmt, "update %s set flags=%d where local_id=%d;",
	   tabp->tabname, flags, id);
  return statementscm (conp, stmt);
}

/*
 * callback function for verify_children
 */
static int verifyChildCRL (scmcon *conp, scmsrcha *s, int idx)
{
  crl_fields *cf;
  X509_CRL   *x = NULL;
  int   crlsta = 0;
  int   sta = 0;
  unsigned int i, id;
  int typ, chainOK, x509sta;
  char pathname[PATH_MAX];

  idx = idx;
  // try verifying crl
  sprintf (pathname, "%s/%s", (char *) s->vec[0].valptr,
	   (char *) s->vec[1].valptr);
  typ = infer_filetype (pathname);
  cf = crl2fields((char *) s->vec[1].valptr, pathname, typ,
		  &x, &sta, &crlsta);
  sta = verify_crl(conp, x, cf->fields[CRF_FIELD_AKI],
		   cf->fields[CRF_FIELD_ISSUER], &x509sta, &chainOK);
  id = *((unsigned int *) (s->vec[2].valptr));
  // if invalid, delete it
  if (sta < 0) {
    deletebylid (conp, theCRLTable, id);
    return sta;
  }
  // otherwise, validate it and do its revocations
  sta = updateValidFlags (conp, theCRLTable, id,
			  *((unsigned int *) (s->vec[3].valptr)), 1);
  for (i = 0; i < cf->snlen; i++) {
    model_cfunc (theSCMP, conp, cf->fields[CRF_FIELD_ISSUER],
		 cf->fields[CRF_FIELD_AKI],
		 ((unsigned long long *)cf->snlist)[i]);
  }
  return 0;
}

/*
 * callback function for verify_children
 */
static int verifyChildROA (scmcon *conp, scmsrcha *s, int idx)
{
  struct ROA *r = NULL;
  int typ, chainOK, sta;
  char pathname[PATH_MAX];
  unsigned int id;

  idx = idx;
  // try verifying crl
  sprintf (pathname, "%s/%s", (char *) s->vec[0].valptr,
	   (char *) s->vec[1].valptr);
  typ = infer_filetype (pathname);
  sta = roaFromFile(pathname, typ>=OT_PEM_OFFSET ? FMT_PEM : FMT_DER, 1, &r);
  if (sta < 0)
    return sta;
  sta = verify_roa(conp, r, (char *)roaSKI(r), &chainOK);
  roaFree(r);
  id = *((unsigned int *) (s->vec[2].valptr));
  // if invalid, delete it
  if (sta < 0) {
    deletebylid (conp, theROATable, id);
    return sta;
  }
  // otherwise, validate it
  sta = updateValidFlags (conp, theROATable, id,
			  *((unsigned int *) (s->vec[3].valptr)), 1);
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
static scmsrcha crlSrch;
static scmsrch  crlSrch1[4];
static char crlWhere[600];
static unsigned long crlBlah = 0;
static int crlNeedsInit = 1;

/*
 * utility function for verifyChildren
 */
static int verifyChildCert (scmcon *conp, PropData *data)
{
  X509 *x = NULL;
  int   x509sta, sta, chainOK;
  char  pathname[PATH_MAX];

  sprintf (pathname, "%s/%s", data->dirname, data->filename);
  x = readCertFromFile (pathname, &sta);
  if ( x == NULL )
    return ERR_SCM_X509;
  sta = verify_cert(conp, x, 0, data->aki, data->issuer, &x509sta, &chainOK);
  if (sta < 0) {
    deletebylid (conp, theCertTable, data->id);
    return sta;
  }
  updateValidFlags (conp, theCertTable, data->id, data->flags, 1);
  if (crlNeedsInit) {
    crlNeedsInit = 0;
    crlSrch.sname = NULL;
    crlSrch.where = NULL;
    crlSrch.ntot = 4;
    crlSrch.nused = 0;
    crlSrch.context = &crlBlah;
    crlSrch.wherestr = crlWhere;
    crlSrch.vec = crlSrch1;
    addcolsrchscm (&crlSrch, "dirname", SQL_C_CHAR, 4096);
    addcolsrchscm (&crlSrch, "filename", SQL_C_CHAR, 256);
    addcolsrchscm (&crlSrch, "local_id", SQL_C_ULONG,
		   sizeof(unsigned int));
    addcolsrchscm (&crlSrch, "flags", SQL_C_ULONG, sizeof(unsigned int));
  }
  sprintf (crlWhere, "aki=\"%s\" and issuer=\"%s\" and (flags%%%d)>=%d",
	   data->ski, data->subject,
	   2*SCM_FLAG_NOCHAIN, SCM_FLAG_NOCHAIN);
  sta = searchscm (conp, theCRLTable, &crlSrch, NULL, verifyChildCRL,
		   SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN);
  sprintf (crlWhere, "ski=\"%s\" and (flags%%%d)>=%d",
	   data->ski, 2*SCM_FLAG_NOCHAIN, SCM_FLAG_NOCHAIN);
  sta = searchscm (conp, theROATable, &crlSrch, NULL, verifyChildROA,
		   SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN);
  return 0;
}


typedef struct _mcf
{
  int     did;
  int     toplevel;
} mcf;


/*
  This function returns the number of valid certificates that
  have subject=IS and ski=AK, or a negative error code on failure.
*/

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

static int countvalidparents(scmcon *conp, char *IS, char *AK)
{
  unsigned int flags = 0;
  scmsrcha srch;
  scmsrch  srch1;
  scmkva   where;
  scmkv    w[2];
  mcf      mymcf;
  char     ws[256];
  char    *now;
  int      sta;

  w[0].column = "ski";
  w[0].value = AK;
  if (IS != NULL) {
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
  if ( now == NULL )
    return(sta);
  (void)sprintf(ws, "valfrom < \"%s\" AND \"%s\" < valto", now, now);
  free((void *)now);
  srch.wherestr = &ws[0];
  mymcf.did = 0;
  srch.context = (void *)&mymcf;
  sta = searchscm(conp, theCertTable, &srch, NULL, cparents,
		  SCM_SRCH_DOVALUE_ALWAYS);
  if ( sta < 0 )
    return(sta);
  return mymcf.did;
}


// static variables for efficiency, so only need to set up query once
static scmsrcha roaSrch;
static scmsrch  roaSrch1[2];
static char roaWhere[600];
static unsigned long roaBlah = 0;
static int roaNeedsInit = 1;

/*
 * callback function for invalidateChildCert
 */
static int revoke_roa(scmcon *conp, scmsrcha *s, int idx)
{
  unsigned int lid, flags;
  char   ski[512];

  UNREFERENCED_PARAMETER(idx);
  lid = *(unsigned int *)(s->vec[0].valptr);
  flags = *(unsigned int *)(s->vec[2].valptr);
  (void)strcpy(ski, (char *)(s->vec[1].valptr));
  if ( countvalidparents(conp, NULL, ski) > 0 )
    return(0);
  updateValidFlags (conp, theROATable, lid, flags, 0);
  return 0;
}

/*
 * utility function for verify_children
 */
static int invalidateChildCert (scmcon *conp, PropData *data)
{
  int sta;
  if (countvalidparents (conp, data->issuer, data->aki) > 0)
    return -1;
  sta = updateValidFlags (conp, theCertTable, data->id, data->flags, 0);
  return sta;
}


// static variables for efficiency, so only need to set up query once
static scmsrcha childrenSrch;
static scmsrch  childrenSrch1[8];
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
  propData[propListSize].aki = strdup (s->vec[6].valptr);
  propData[propListSize].issuer = strdup (s->vec[7].valptr);
  propListSize++;
  return 0;
}

/*
 * verify the children certs of the current cert
 */
static int verifyOrNotChildren (scmcon *conp, char *ski, char *subject,
				int doVerify)
{
  int isRoot = 1;
  int doIt, idx;
  int flag = doVerify ? SCM_FLAG_NOCHAIN : SCM_FLAG_VALID;

  // initialize query first time through
  if (childrenNeedsInit) {
    childrenNeedsInit = 0;
    childrenSrch.sname = NULL;
    childrenSrch.where = NULL;
    childrenSrch.ntot = 8;
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
    addcolsrchscm (&childrenSrch, "aki", SQL_C_CHAR, 128);
    addcolsrchscm (&childrenSrch, "issuer", SQL_C_CHAR, 512);
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
    if (isRoot)
      doIt = 1;
    else if (doVerify)
      doIt = verifyChildCert (conp, &propData[idx]) == 0;
    else
      doIt = invalidateChildCert (conp, &propData[idx]) == 0;
    if (doIt) {
      sprintf(childrenWhere,
	  "aki=\"%s\" and ski<>\"%s\" and issuer=\"%s\" and (flags%%%d)>=%d",
	      propData[idx].ski, propData[idx].ski,
	      propData[idx].subject, 2 * flag, flag);
      if (! doVerify) {
	if (roaNeedsInit) {
	  roaNeedsInit = 0;
	  roaSrch.sname = NULL;
	  roaSrch.where = NULL;
	  roaSrch.ntot = 3;
	  roaSrch.nused = 0;
	  roaSrch.context = &roaBlah;
	  roaSrch.wherestr = roaWhere;
	  roaSrch.vec = roaSrch1;
	  addcolsrchscm (&roaSrch, "local_id", SQL_C_ULONG,
			 sizeof(unsigned int));
	  addcolsrchscm (&roaSrch, "ski", SQL_C_CHAR, 128);
	  addcolsrchscm (&roaSrch, "flags", SQL_C_ULONG, sizeof(unsigned int));
	}
	sprintf (roaWhere, "ski=\"%s\" and (flags%%%d)>=%d",
		 propData[idx].ski, 2*SCM_FLAG_VALID, SCM_FLAG_VALID);
	searchscm(conp, theROATable, &roaSrch, NULL, revoke_roa,
		  SCM_SRCH_DOVALUE_ALWAYS);
      }
    }
    if (! isRoot) {
      free (propData[idx].filename);
      free (propData[idx].dirname);
      free (propData[idx].ski);
      free (propData[idx].subject);
      free (propData[idx].aki);
      free (propData[idx].issuer);
    }
    if (doIt)
      searchscm (conp, theCertTable, &childrenSrch, NULL, registerChild,
		 SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN);
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
  int   ct = UN_CERT;
  int   sta = 0;
  int   chainOK;

  initTables (scmp);
  cf = cert2fields(outfile, outfull, typ, &x, &sta, &x509sta);
  if ( cf == NULL || x == NULL )
    {
      if ( cf != NULL )
	freecf(cf);
      if ( x != NULL )
	X509_free(x);
      return(sta);
    }
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
// verify that the cert matches the rescert profile
  if ( utrust > 0 )
    ct = TA_CERT;
  else
    ct = ( cf->flags & SCM_FLAG_CA ) ? CA_CERT : EE_CERT;
  sta = rescert_profile_chk(x, ct);
// verify the cert
  if ( sta == 0 ) {
    sta = verify_cert(conp, x, utrust, cf->fields[CF_FIELD_AKI],
		     cf->fields[CF_FIELD_ISSUER], &x509sta, &chainOK);
  }
  // check that no crls revoking this cert
  if (sta == 0) {
    sta = cert_revoked (scmp, conp, cf->fields[CF_FIELD_SN],
			cf->fields[CF_FIELD_ISSUER]);
  }
// actually add the certificate
  if ( sta == 0 )
    {
      cf->flags |= (chainOK ? SCM_FLAG_VALID : SCM_FLAG_NOCHAIN);
      sta = add_cert_internal(scmp, conp, cf, cert_id);
    }
// try to validate children of cert
  if (sta == 0) {
    sta = verifyOrNotChildren (conp, cf->fields[CF_FIELD_SKI],
			       cf->fields[CF_FIELD_SUBJECT], 1);
  }
  freecf(cf);
  // if change verify_cert so that not pushing on stack, change this
  if (! (cf->flags | SCM_FLAG_TRUSTED)) {
    X509_free(x);
  }
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
  unsigned int i;
  int chainOK, x509sta;

  UNREFERENCED_PARAMETER(utrust);
  cf = crl2fields(outfile, outfull, typ, &x, &sta, &crlsta);
  if ( cf == NULL || x == NULL )
    {
      if ( cf != NULL )
	freecrf(cf);
      if ( x != NULL )
	X509_CRL_free(x);
      return(sta);
    }
  cf->dirid = id;
// first verify the CRL
  sta = verify_crl(conp, x, cf->fields[CRF_FIELD_AKI],
		   cf->fields[CRF_FIELD_ISSUER], &x509sta, &chainOK);
// then add the CRL
  if (sta == 0) {
    cf->flags |= chainOK ? SCM_FLAG_VALID : SCM_FLAG_NOCHAIN;
    sta = add_crl_internal(scmp, conp, cf);
  }
// and do the revocations
  if ((sta == 0) && chainOK) {
    for (i = 0; i < cf->snlen; i++) {
      model_cfunc (scmp, conp, cf->fields[CRF_FIELD_ISSUER],
		   cf->fields[CRF_FIELD_AKI],
		   ((unsigned long long *)cf->snlist)[i]);
    }
  }
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
  char *ski;
  int   asid;
  int   sta, chainOK;

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
  sta = verify_roa (conp, r, ski, &chainOK);
  roaFree(r);
  if ( sta < 0 )
    return(sta);
  sta = add_roa_internal(scmp, conp, outfile, id, ski, asid, chainOK);
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
  unsigned int id = 0, obj_id = 0;
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
  initTables (scmp);
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
  int     sta;

  UNREFERENCED_PARAMETER(idx);
  lid = *(unsigned int *)(s->vec[0].valptr);
  sta = deletebylid(conp, theCertTable, lid);
  return verifyOrNotChildren (conp, (char *) s->vec[1].valptr,
			      (char *) s->vec[2].valptr, 0);
}

/*
 * Fill in the columns for a search with revoke_cert_and_children as callback
 */
static void fillInColumns (scmsrch *srch1, unsigned int *lid, char *ski,
			   char *subject, scmsrcha *srch)
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
  srch->vec = srch1;
  srch->sname = NULL;
  srch->ntot = 3;
  srch->nused = 3;
  srch->vald = 0;
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
  scmsrch  srch1, srch2[5];
  scmkva   where;
  scmkva   dwhere;
  scmkv    one;
  scmkv    dtwo[2];
  scmtab  *thetab;
  char did[24];
  int  typ;
  int  sta;
  unsigned int lid;
  char     ski[512];
  char     subject[512];
  mcf      mymcf;

  if ( scmp == NULL || conp == NULL || conp->connected == 0 ||
       outfile == NULL || outdir == NULL || outfull == NULL )
    return(ERR_SCM_INVALARG);
// determine its filetype
  typ = infer_filetype(outfull);
  if ( typ < 0 )
    return(typ);
// find the directory
  initTables (scmp);
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
  sta = searchscm(conp, theDirTable, &srch, NULL, ok, SCM_SRCH_DOVALUE_ALWAYS);
  if ( sta < 0 )
    return(sta);

  // fill in where structure
  dtwo[0].column = "filename";
  dtwo[0].value = outfile;
  dtwo[1].column = "dir_id";
  (void)sprintf(did, "%u", id);
  dtwo[1].value = did;
  dwhere.vec = &dtwo[0];
  dwhere.ntot = 2;
  dwhere.nused = 2;
  dwhere.vald = 0;

// delete the object based on the type
// note that the directory itself is not deleted
  thetab = NULL;
  switch ( typ )
    {
    case OT_CER:
    case OT_CER_PEM:
    case OT_UNKNOWN:
    case OT_UNKNOWN+OT_PEM_OFFSET:
      thetab = theCertTable;
      mymcf.did = 0;
      mymcf.toplevel = 1;
      fillInColumns (srch2, &lid, ski, subject, &srch);
      srch.where = &dwhere;
      srch.context = &mymcf;
      sta = searchscm(conp, thetab, &srch, NULL, revoke_cert_and_children,
		      SCM_SRCH_DOVALUE_ALWAYS);
      break;
    case OT_CRL:
    case OT_CRL_PEM:
      thetab = theCRLTable;
      break;
    case OT_ROA:
    case OT_ROA_PEM:
      thetab = theROATable;
      break;
    default:
      sta = ERR_SCM_INTERNAL;
      break;
    }
  if ( thetab == NULL )
    sta = ERR_SCM_NOSUCHTAB;
  if ( sta < 0 )
    return(sta);
  sta = deletescm(conp, thetab, &dwhere);
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
  unsigned int lid;
  scmsrcha srch;
  scmsrch  srch1[5];
  scmkva   where;
  scmkv    w[3];
  mcf      mymcf;
  char     ski[512];
  char     subject[512];
  char     sno[24];
  int      sta;

  if ( scmp == NULL || conp == NULL || conp->connected == 0 )
    return(ERR_SCM_INVALARG);
  if ( issuer == NULL || issuer[0] == 0 || aki == NULL || aki[0] == 0 ||
       sn == 0 )
    return(0);
  initTables (scmp);
  mymcf.did = 0;
  mymcf.toplevel = 1;
  w[0].column = "issuer";
  w[0].value = issuer;
  (void)sprintf(sno, "%lld", sn);
  w[1].column = "sn";
  w[1].value = &sno[0];
  w[2].column = "aki";
  w[2].value = aki;
  where.vec = &w[0];
  where.ntot = 3;
  where.nused = 3;
  where.vald = 0;
  fillInColumns (srch1, &lid, ski, subject, &srch);
  srch.where = &where;
  srch.wherestr = NULL;
  srch.context = &mymcf;
  sta = searchscm(conp, theCertTable, &srch, NULL, revoke_cert_and_children,
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
  pflags = *(unsigned int *)(s->vec[4].valptr);
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
  sta = setflagsscm(conp, theCertTable, &where, pflags);
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
  pflags = *(unsigned int *)(s->vec[4].valptr);
  pflags &= ~SCM_FLAG_VALID;
  pflags |= SCM_FLAG_NOTYET;
  sta = setflagsscm(conp, theCertTable, &where, pflags);
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
  unsigned int lid;
  scmsrcha srch;
  scmsrch  srch1[5];
  mcf   mymcf;
  char  skistr[512];
  char  subjstr[512];
  char *vok;
  char *vf;
  char *vt;
  char *now;
  int   retsta = 0;
  int   sta = 0;

  if ( scmp == NULL || conp == NULL || conp->connected == 0 )
    return(ERR_SCM_INVALARG);
  initTables (scmp);
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
  fillInColumns (srch1, &lid, skistr, subjstr, &srch);
  srch.where = NULL;
  srch.wherestr = vok;
  mymcf.did = 0;
  mymcf.toplevel = 0;
  srch.context = (void *)&mymcf;
  sta = searchscm(conp, theCertTable, &srch, NULL,
		  certmaybeok, SCM_SRCH_DOVALUE_ALWAYS);
  free((void *)vok);
  if ( sta < 0 && sta != ERR_SCM_NODATA )
    retsta = sta;
// search for certificates that are too new
  srch.wherestr = vf;
  // ?????????????? no need to call this here; instead ??????????
  // ?????????????? check when first put in ???????????? GAGNON
  sta = searchscm(conp, theCertTable, &srch, NULL,
		  certtoonew, SCM_SRCH_DOVALUE_ALWAYS);
  free((void *)vf);
  if ( sta < 0 && sta != ERR_SCM_NODATA && retsta == 0 )
    retsta = sta;
// search for certificates that are too old
  srch.wherestr = vt;
  sta = searchscm(conp, theCertTable, &srch, NULL,
		  certtooold, SCM_SRCH_DOVALUE_ALWAYS);
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
  char   *now;
  char    what;
  int     sta = 0;

  if ( scmp == NULL || conp == NULL || conp->connected == 0 ||
       whichcli == NULL || whichcli[0] == 0 )
    return(ERR_SCM_INVALARG);
  what = toupper(whichcli[0]);
  if ( what != 'R' && what != 'Q' && what != 'C' && what != 'G' )
    return(ERR_SCM_INVALARG);
  initTables (scmp);
  conp->mystat.tabname = "METADATA";
  now = LocalTimeToDBTime(&sta);
  if ( now == NULL )
    return(sta);
  sta = updateranlastscm(conp, theMetaTable, what, now);
  free((void *)now);
  return(sta);
}

/*
  Given the SKI of a ROA, this function returns the X509 * structure
  for the corresponding EE certificate (or NULL on error).
*/

void *roa_parent(scm *scmp, scmcon *conp, char *ski, char **fn, int *stap)
{
  initTables (scmp);
  return parent_cert (conp, ski, NULL, stap, fn);
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
