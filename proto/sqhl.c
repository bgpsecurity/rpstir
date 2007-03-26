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

#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "diru.h"
#include "myssl.h"
#include "err.h"

/*
  Find a directory in the directory table, or create it if it is not found.
  Return the id in idp. The function returns 0 on success and a negative error
  code on failure.

  It is assumed that the existence of the putative directory has already been
  verified.
*/

int findorcreatedir(scm *scmp, scmcon *conp, scmtab *mtab, char *dirname,
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
  if ( mtab == NULL )
    {
      mtab = findtablescm(scmp, "METADATA");
      if ( mtab == NULL )
	{
	  conp->mystat.tabname = "METADATA";
	  return(ERR_SCM_NOSUCHTAB);
	}
    }
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
  sta = searchorcreatescm(scmp, conp, tabp, mtab, srch, &ins, idp);
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

static int add_cert_internal(scm *scmp, scmcon *conp, cert_fields *cf)
{
  unsigned int cert_id;
  scmtab  *ctab;
  scmkva   aone;
  scmkv    cols[CF_NFIELDS+3];
  char *ptr;
  char  flagn[24];
  char  lid[24];
  char  did[24];
  int   idx = 0;
  int   sta;
  int   i;

  ctab = findtablescm(scmp, "CERTIFICATE");
  if ( ctab == NULL )
    return(ERR_SCM_NOSUCHTAB);
  sta = getmaxidscm(scmp, conp, NULL, "CERTIFICATE", &cert_id);
  if ( sta < 0 )
    return(sta);
  cert_id++;
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
  (void)sprintf(lid, "%u", cert_id);
  cols[idx].column = "local_id";
  cols[idx++].value = lid;
  (void)sprintf(did, "%u", cf->dirid);
  cols[idx].column = "dir_id";
  cols[idx++].value = did;
  aone.vec = &cols[0];
  aone.ntot = CF_NFIELDS+3;
  aone.nused = idx;
  aone.vald = 0;
  sta = insertscm(conp, ctab, &aone);
  if ( sta < 0 )
    return(sta);
  sta = setmaxidscm(scmp, conp, NULL, "CERTIFICATE", cert_id);
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
  Get the parent certificate by using the aki of "x" to look it
  up in the db. If "x" has already been broken down in "cf" just
  use the aki from there, otherwise look it up from "x". The
  db lookup will return the filename and directory name of the
  parent cert, as well as its flags. Set those flags into "pflags"
*/

static X509 *parent_cert(scm *scmp, scmcon *conp, X509 *x,
			 cert_fields *cf, int *stap, unsigned int *pflags)
{
  unsigned long blah = 0;
  unsigned long dblah = 0;
  unsigned int  dirid = 0;
  scmtab  *ctab;
  scmtab  *dtab;
  scmsrcha srch;
  scmsrch  srch1[3];
  scmsrcha dsrch;
  scmsrch  dsrch1;
  scmkva where;
  scmkv  one;
  scmkva dwhere;
  scmkv  done;
  X509  *px = NULL;
  BIO   *bcert = NULL;
  char *aki = NULL;
  char *daki = NULL;
  char *ofile;			/* filename component */
  char *dfile;			/* directory component */
  char *ofullname;		/* full pathname */
  char  cdirid[24];
  int   alld = 0;
  int   x509sta = 0;
  int   typ;

  *pflags = 0;
  *stap = 0;
  ctab = findtablescm(scmp, "CERTIFICATE");
  if ( ctab == NULL )
    {
      *stap = ERR_SCM_NOSUCHTAB;
      return(NULL);
    }
  dtab = findtablescm(scmp, "DIRECTORY");
  if ( dtab == NULL )
    {
      *stap = ERR_SCM_NOSUCHTAB;
      return(NULL);
    }
  if ( cf == NULL )
    {
      cf = cert2fields(NULL, NULL, 0, &x, stap, &x509sta);
      if ( cf == NULL )
	return(NULL);
      alld++;
    }
  aki = cf->fields[CF_FIELD_AKI];
  if ( aki == NULL )
    {
      *stap = ERR_SCM_NOAKI;
      if ( alld > 0 && cf != NULL )
	freecf(cf);
    }
  daki = strdup(aki);
  if ( alld > 0 && cf != NULL )
    freecf(cf);
  if ( daki == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  ofile = (char *)calloc(PATH_MAX, sizeof(char));
  if ( ofile == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
// find the entry whose ski is our aki, e.g. our parent
  one.column = "ski";
  one.value = daki;
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
  srch1[2].valptr = (void *)pflags;
  srch1[2].valsize = sizeof(unsigned int);
  srch1[2].avalsize = 0;
  srch.vec = (&srch1[0]);
  srch.sname = NULL;
  srch.ntot = 3;
  srch.nused = 3;
  srch.vald = 0;
  srch.where = &where;
  srch.context = &blah;
  *stap = searchscm(conp, ctab, &srch, NULL, ok, SCM_SRCH_DOVALUE_ALWAYS);
  free((void *)daki);
  if ( *stap < 0 )
    {
      free((void *)ofile);
      return(NULL);
    }
// if the certificate is not marked as valid, then just bail
  if ( ((*pflags) & SCM_FLAG_VALID) == 0 )
    {
      *stap = ERR_SCM_NOTVALID;
      return(NULL);
    }
// now find the directory name from the directory id
  dfile = (char *)calloc(PATH_MAX, sizeof(char));
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
  dsrch.context = &dblah;
  *stap = searchscm(conp, dtab, &dsrch, NULL, ok, SCM_SRCH_DOVALUE_ALWAYS);
  if ( *stap < 0 )
    {
      free((void *)ofile);
      free((void *)dfile);
      return(NULL);
    }
// construct the full pathname
  ofullname = (char *)calloc(PATH_MAX, sizeof(char));
  if ( ofullname == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  (void)sprintf(ofullname, "%s/%s", dfile, ofile);
  free((void *)dfile);
  free((void *)ofile);
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
  free((void *)ofullname);
  return(px);
}

/*
  Certificate verification code by mudge
*/

static int verify_cert(scm *scmp, scmcon *conp, X509 *x,
		       cert_fields *cf, int *x509stap)
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
  if ( cf->flags & SCM_FLAG_TRUSTED )
    sk_X509_push(sk_trusted, x);
  else
    {
      pflags = 0;
      parent = parent_cert(scmp, conp, x, cf, &sta, &pflags);
      while ( parent != NULL )
	{
	  if ( pflags & SCM_FLAG_TRUSTED )
	    {
	      sk_X509_push(sk_trusted, parent);
	      break;
	    }
	  else
	    {
	      sk_X509_push(sk_untrusted, parent);
	      pflags = 0;
	      parent = parent_cert(scmp, conp, parent, NULL, &sta, &pflags);
	    }
	}
    }
  if ( sta == 0 )
    sta = checkit(cert_ctx, x, sk_untrusted, sk_trusted, purpose, NULL);
  *x509stap = cbx509err;
  sk_X509_free(sk_untrusted);
  sk_X509_free(sk_trusted);
  X509_STORE_free(cert_ctx);
  X509_VERIFY_PARAM_free(vpm);
  return(sta);
}

/*
  Add a certificate to the DB. If utrust is set, check that it is
  self-signed first. Validate the cert and add it.

  This function returns 0 on success and a negative error code on
  failure.
*/

int add_cert(scm *scmp, scmcon *conp, char *outfile, char *outfull,
	     unsigned int id, int utrust, int typ)
{
  cert_fields *cf;
  X509 *x = NULL;
  int   x509sta = 0;
  int   sta = 0;

  cf = cert2fields(outfile, outfull, typ, &x, &sta, &x509sta);
  if ( cf == NULL || x == NULL )
    return(sta);
  cf->dirid = id;
  if ( strcmp(cf->fields[CF_FIELD_SUBJECT], cf->fields[CF_FIELD_ISSUER]) == 0 )
    cf->flags |= SCM_FLAG_SS;
  if ( utrust > 0 )
    {
      if ( (cf->flags & SCM_FLAG_SS) == 0 )
	{
	  freecf(cf);
	  X509_free(x);
	  return(ERR_SCM_NOTSS);
	}
      cf->flags |= SCM_FLAG_TRUSTED;
    }
// verify the cert
  sta = verify_cert(scmp, conp, x, cf, &x509sta);
// actually add the certificate
  if ( sta == 0 )
    {
      cf->flags |= SCM_FLAG_VALID;
      sta = add_cert_internal(scmp, conp, cf);
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
  UNREFERENCED_PARAMETER(utrust);

  return(0);			/* GAGNON */
}

/*
  Add a ROA to the DB.  This function returns 0 on success and a
  negative error code on failure.
*/

int add_roa(scm *scmp, scmcon *conp, char *outfile, char *outfull,
	    unsigned int id, int utrust, int typ)
{
  UNREFERENCED_PARAMETER(utrust);

  return(0);			/* GAGNON */
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
  unsigned int id;
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
  sta = findorcreatedir(scmp, conp, NULL, outdir, &id);
  if ( sta < 0 )
    return(sta);
// add the object based on the type
  switch ( typ )
    {
    case OT_CER:
    case OT_CER_PEM:
    case OT_UNKNOWN:
    case OT_UNKNOWN+OT_PEM_OFFSET:
      sta = add_cert(scmp, conp, outfile, outfull, id, utrust, typ);
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

int delete_object(scm *scmp, scmcon *conp, char *outfile, char *outdir, char *outfull)
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
  srch.context = &blah;
  sta = searchscm(conp, thetab, &srch, NULL, ok, SCM_SRCH_DOVALUE_ALWAYS);
  if ( sta < 0 )
    return(sta);
// delete the object based on the type
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
