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
#include "err.h"

/*
  Find a directory in the directory table, or create it if it is not found.
  Return the id in idp. The function returns 0 on success and a negative error code
  on failure.

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

/*
  Add a certificate to the DB. If utrust is set, check that it is
  self-signed first.

  This function returns 0 on success and a negative error code on
  failure.
*/

int add_cert(scm *scmp, scmcon *conp, char *outfile, char *outfull,
	     unsigned int id, int utrust, int typ)
{
  return(0);			/* GAGNON */
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
