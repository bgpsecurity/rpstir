/*
  $Id$
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include "scm.h"
#define  SCM_DEFINED_HERE
#include "scmmain.h"
#undef   SCM_DEFINED_HERE

/*
  Free all the memory allocated in building an scm
*/

static void freescmtable(scmtab *tabp)
{
  int i;

  if ( tabp == NULL )
    return;
  if ( tabp->tabname != NULL )
    {
      free((void *)(tabp->tabname));
      tabp->tabname = NULL;
    }
  if ( tabp->hname != NULL )
    {
      free((void *)(tabp->hname));
      tabp->hname = NULL;
    }
  if ( tabp->tstr != NULL )
    {
      free((void *)(tabp->tstr));
      tabp->tstr = NULL;
    }
  if ( tabp->cols == NULL )
    return;
  for(i=0;i<tabp->ncols;i++)
    {
      if ( tabp->cols[i] != NULL )
	{
	  free((void *)(tabp->cols[i]));
	  tabp->cols[i] = NULL;
	}
    }
  free((void *)(tabp->cols));
  tabp->cols = NULL;
}

static void freescm(scm *scmp)
{
  int i;

  if ( scmp == NULL )
    return;
  if ( scmp->db == NULL )
    {
      free((void *)(scmp->db));
      scmp->db = NULL;
    }
  if ( scmp->dbuser == NULL )
    {
      free((void *)(scmp->dbuser));
      scmp->dbuser = NULL;
    }
  if ( scmp->dsn != NULL )
    {
      free((void *)(scmp->dsn));
      scmp->dsn = NULL;
    }
  if ( scmp->tables != NULL )
    {
      for(i=0;i<scmp->ntables;i++)
	freescmtable(&scmp->tables[i]);
      free((void *)(scmp->tables));
      scmp->tables = NULL;
    }
  free((void *)scmp);
}

static char *firsttok(char *ptr)
{
  char *run;
  char *out;
  char  c;
  int   cnt = 0;

  if ( ptr == NULL || ptr[0] == 0 )
    return(NULL);
  run = ptr;
  while ( 1 )
    {
      c = *run++;
      if ( isspace(c) || c == 0 )
	break;
      cnt++;
    }
  if ( cnt == 0 )
    return(NULL);
  out = (char *)calloc(cnt+1, sizeof(char));
  if ( out == NULL )
    return(NULL);
  (void)strncpy(out, ptr, cnt);
  out[cnt] = 0;
  return(out);
}

static int makecolumns(scmtab *outtab)
{
  char *ptr;
  char *dp;
  int  rcnt = 0;
  int  cnt = 0;

  if ( outtab == NULL || outtab->tstr == NULL )
    return(-1);
  dp = strdup(outtab->tstr);
  if ( dp == NULL )
    return(-2);
  ptr = strtok(dp, ",");
  while ( ptr != NULL && ptr[0] != 0 )
    {
      if ( islower(ptr[0]) && !isspace(ptr[0]) )
	cnt++;
      ptr = strtok(NULL, ",");
    }
  free(dp);
  outtab->cols = (char **)calloc(cnt, sizeof(char *));
  if ( outtab->cols == NULL )
    return(-3);
  dp = strdup(outtab->tstr);
  if ( dp == NULL )
    return(-4);
  ptr = strtok(dp, ",");
  while ( ptr != NULL && ptr[0] != 0 )
    {
      if ( isspace(ptr[0]) || ptr[0] == 0 )
	break;
      outtab->cols[rcnt] = firsttok(ptr);
      if ( outtab->cols[rcnt] == NULL )
	{
	  free(dp);
	  return(-rcnt-5);
	}
      rcnt++;
      ptr = strtok(NULL, ",");
    }
  free(dp);
  outtab->ncols = rcnt;
  return(0);
}

static int prepareonetable(scmtab *outtab, scmtab *intab)
{
  int  sta;

  if ( outtab == NULL || intab == NULL )
    return(-1);
  outtab->tabname = strdup(intab->tabname);
  if ( outtab->tabname == NULL )
    return(-2);
  outtab->hname = strdup(intab->hname);
  if ( outtab->hname == NULL )
    return(-3);
  outtab->tstr = strdup(intab->tstr);
  if ( outtab->tstr == NULL )
    return(-4);
  sta = makecolumns(outtab);
  return(sta);
}

static int preparetables(scm *scmp, scmtab *scmtabbuilderp, int sz)
{
  int cnt = 0;
  int sta;
  int i;

  if ( scmp == NULL || scmtabbuilderp == NULL || sz <= 0 )
    return(-1);
  scmp->tables = (scmtab *)calloc(sz, sizeof(scmtab));
  if ( scmp->tables == NULL )
    return(-2);
  for(i=0;i<sz;i++)
    {
      sta = prepareonetable(&scmp->tables[i],
			    &scmtabbuilderp[i]);
      if ( sta < 0 )
	return(sta);
      cnt++;
    }
  scmp->ntables = cnt;
  return(0);
}

scm *initscm(void)
{
  scm  *scmp;
  char *tmp;
  int   len;
  int   sta;

  scmp = (scm *)calloc(1, sizeof(scm));
  if ( scmp == NULL )
    return(NULL);
  scmp->db = strdup(APKI_DB);
  if ( scmp->db == NULL )
    {
      freescm(scmp);
      return(NULL);
    }
  scmp->dbuser = strdup(APKI_DBUSER);
  if ( scmp->dbuser == NULL )
    {
      freescm(scmp);
      return(NULL);
    }
  len = strlen(APKI_DSN) + strlen(APKI_DB) + strlen(APKI_DBUSER) + 30;
  scmp->dsn = (char *)calloc(len, sizeof(char));
  if ( scmp->dsn == NULL )
    {
      freescm(scmp);
      return(NULL);
    }
  (void)sprintf(scmp->dsn, "%s;DATABASE=%s;USER=%s;",
		APKI_DSN, APKI_DB, APKI_DBUSER);
  sta = preparetables(scmp, &scmtabbuilder[0],
		      sizeof(scmtabbuilder)/sizeof(scmtab));
  if ( sta < 0 )
    {
      freescm(scmp);
      return(NULL);
    }
  return(scmp);
}

#ifdef TEST

int main(void)
{
  scm *scmp;
  int  i;

  (void)setbuf(stdout, NULL);
  scmp = initscm();
  (void)printf("DSN name is %s\n", scmp->dsn);
  (void)printf("Number of tables is %d\n", scmp->ntables);
  for(i=0;i<scmp->ntables;i++)
    {
      (void)printf("\t\t%d\t%s\t%s\n", i,
		   scmp->tables[i].tabname,
		   scmp->tables[i].hname);
    }
  return(0);
}

#endif
