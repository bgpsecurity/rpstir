/*
  $Id$
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "diru.h"

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

  if ( conp == NULL || conp->connected == 0 || dirname == NULL || dirname[0] == 0 ||
       idp == NULL )
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
