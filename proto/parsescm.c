/*
  $Id$
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include "scm.h"

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

/*
  Remove comments from a line in place
*/

static void remcom(char *buf)
{
  char *sharp;

  if ( buf == NULL || buf[0] == 0 )
    return;
  sharp = strchr(buf, '#');
  if ( sharp != NULL )
    *sharp = 0;
}

/*
  Remove leading and trailing white space from a line in place
*/

static void trimwhite(char *buf)
{
  char *inptr;
  char  c;
  int   len;
  int   incnt = 0;
  int   oucnt = 0;

  if ( buf == NULL || buf[0] == 0 )
    return;
  inptr = buf;
  while ( 1 )
    {
      c = *inptr++;
      if ( c == 0 || ! isspace(c) )
	break;
      incnt++;
    }
  len = strlen(buf);
  inptr = buf + len - 1;
  while ( inptr >= buf )
    {
      c = *inptr--;
      if ( !isspace(c) )
	break;
      oucnt++;
    }
  if ( (incnt+oucnt) >= len )
    {
      buf[0] = 0;
      return;
    }
  len -= oucnt;
  buf[len] = 0;
  if ( incnt > 0 )
    {
      inptr = buf + incnt;
      while ( incnt-- > 0 )
	*buf++ = *inptr++;
    }
}

/*
  Accumulate a bunch of lines up to a closing ;. Put the indicated
  lines in the indicated pointer. Return the line number on success
  and a negative error code on failure.
*/

static int accumlines(char **outp, FILE *fin, int lno, int *lnp)
{
  char  buf[512];
  char *ptr = NULL;
  char *ptr2;
  char *firsttok;
  int   lensofar = 0;
  int   len;

  *outp = NULL;
  while ( fgets(buf, 512, fin) != NULL )
    {
      lno++;
      remcom(buf);
      if ( buf[0] == 0 )
	continue;
      firsttok = strtok(buf, "\t\r\n");
      if ( firsttok == NULL || firsttok[0] == 0 )
	continue;
      if ( firsttok[0] == ';' )
	{
	  trimwhite(ptr);
	  *outp = ptr;
	  return(lno);
	}
      len = strlen(firsttok) + 2;
      if ( lensofar == 0 )
	{
	  ptr = (char *)calloc(len, sizeof(char));
	  if ( ptr == NULL )
	    {
	      *lnp = lno;
	      return(ERR_SCM_NOMEM);
	    }
	  (void)strncpy(ptr, firsttok, len);
	}
      else
	{
	  ptr2 = (char *)calloc(lensofar+len, sizeof(char));
	  if ( ptr2 == NULL )
	    {
	      *lnp = lno;
	      return(ERR_SCM_NOMEM);
	    }
	  (void)strncpy(ptr2, ptr, lensofar);
	  (void)strncpy(ptr2+lensofar, firsttok, len);
	  free((void *)ptr);
	  ptr = ptr2;
	}
      lensofar += len;
      ptr[lensofar-1] = ' ';
    }
  *lnp = lno;
  return(ERR_SCM_NXEOF);
}

/*
  Parse a directive. Return the directive identifier (a strictly
  positive integer) on success, and a negative error code on failure.
*/

static int parsedirective(char *firsttok)
{
  if ( strcasecmp(firsttok, ".dsn") == 0 )
    return(SCM_DIR_DSN);
  else if ( strcasecmp(firsttok, ".tables") == 0 )
    return(SCM_DIR_TABLES);
  else
    return(ERR_SCM_INVALDIR);
}

/*
  Parse a DSN block. It should have exactly one subdirective, a DSN
  subdirective. So, search for a line that begins with DSN and ends
  with a colon. The subdirective's value follows on subsequent line(s).
*/

static int parsedsnblock(FILE *fin, scm *scmp, int lno, int *lnp)
{
  char  buf[512];
  char *firsttok;
  int   done = 0;
  int   err;

  while ( fgets(buf, 512, fin) != NULL && done == 0 )
    {
      lno++;
      if ( buf[0] == 0 )
	continue;
      remcom(buf);
      firsttok = strtok(buf, " \t\r\n");
      if ( firsttok == NULL || firsttok[0] == 0 )
	continue;
      if ( strcasecmp(firsttok, ".end") == 0 )
	{
	  *lnp = lno;
	  return(ERR_SCM_NXDIR);
	}
      if ( firsttok[0] == ';' )
	{
	  *lnp = lno;
	  return(ERR_SCM_NXSDIR);
	}
      if ( strcasecmp(firsttok, "DSN") == 0 )
	{
	  err = accumlines(&scmp->dsn, fin, lno, lnp);
	  if ( err < 0 )
	    return(err);
	  lno = err;
	}
      else if ( strcasecmp(firsttok, ".end") == 0 )
	done++;
      else
	{
	  *lnp = lno;
	  return(ERR_SCM_INVALSDIR);
	}
    }
  if ( done == 0 )		/* fell off the end of the file */
    {
      *lnp = lno;
      return(ERR_SCM_NXEOF);
    }
  return(lno);
}

static int parsetablesblock(FILE *fin, scm *scmp, int mdd, int lno, int *lnp)
{
  return(0);			/* GAGNON */
}

/*
  Parse a directive block starting at line lno+1. The current directive
  and its (possible) modifier are drt and mdd, respectively. Returns the
  current line number on success and a negative error code on failure.
*/

static int parseblock(FILE *fin, scm *scmp, int drt, int mdd,
		      int lno, int *lnp)
{
  switch ( drt )
    {
    case SCM_DIR_DSN:
      return(parsedsnblock(fin, scmp, lno, lnp));
    case SCM_DIR_TABLES:
      return(parsetablesblock(fin, scmp, mdd, lno, lnp));
    default:
      return(ERR_SCM_INVALDIR);
    }
}

/*
  Parse an scm (database schema) file to build a set of table definitions
  and also the DSN name.  The organization of the scm file is a set of blocks.
  Each block begins with a directive and a count. Directives always begin
  with a dot (.).  After the directive are a set of subdirectives. Each
  subdirective begins with a line containing the subdirective name, zero or
  more modifiers, and a colon. On subsequent lines the body of the subdirective
  is found. A subdirective is closed with a semicolon (;) on a line by itself.
  A directive is closed with a .end.  Comments are allowed; they begin with
  # and continue to the end of the line.

  For our purposes there are really only two directives: .dsn and .tables.
  The .dsn directive is used to define the data source name (DSN) of the
  database. The .tables directive takes a modifier, the count of the number
  of tables. Each table is then specified in a subdirective.
*/

static int handlescmfile(scm *scmp, FILE *fin, int *lnp)
{
  char  buf[512];
  char *firsttok;
  char *sectok;
  int   err = 0;
  int   lno = 0;
  int   tcnt;
  int   drt;
  int   mdd;

  while ( fgets(buf, 512, fin) != NULL )
    {
      lno++;
      if ( buf[0] == 0 )
	continue;
      remcom(buf);
      firsttok = strtok(buf, " \t\r\n");
      if ( firsttok == NULL || firsttok[0] == 0 )
	continue;
      if ( firsttok[0] != '.' )	/* must be a directive */
	{
	  *lnp = lno;
	  return(ERR_SCM_NODIR);
	}
      err = parsedirective(firsttok);
      if ( err < 0 )		/* its an error */
	{
	  *lnp = lno;
	  return(err);
	}
      drt = err;		/* its a directive */
      sectok = strtok(NULL, " \t\r\n");
      switch ( drt )
	{
	case SCM_DIR_DSN:	/* no modifiers */
	  if ( sectok != NULL && sectok[0] != 0 )
	    {
	      *lnp = lno;
	      return(ERR_SCM_XMOD);
	    }
	  mdd = 1;		/* exactly one subdirective */
	  break;
	case SCM_DIR_TABLES:	/* one modifier, count of tables */
	  if ( sectok == NULL || sectok[0] == 0 )
	    {
	      *lnp = lno;
	      return(ERR_SCM_NOMOD);
	    }
	  tcnt = atoi(sectok);
	  if ( tcnt <= 0 )
	    {
	      *lnp = lno;
	      return(ERR_SCM_INVALMOD);
	    }
	  scmp->ntables = tcnt;
	  scmp->tables = (scmtab *)calloc(tcnt, sizeof(scmtab));
	  if ( scmp->tables == NULL )
	    return(ERR_SCM_NOMEM);
	  mdd = tcnt;
	  break;
	default:
	  *lnp = lno;
	  return(ERR_SCM_INVALDIR);
	  break;
	}
      err = parseblock(fin, scmp, drt, mdd, lno, lnp);
      if ( err < 0 )
	return(err);
      lno = err;
    }
  if ( scmp->dsn == NULL || scmp->dsn[0] == 0 )
    return(ERR_SCM_NODSN);
  return(err);
}

scm *parsescm(char *fn, int *errp, int *lnp)
{
  FILE *fin;
  scm  *scmp;

  if ( errp == NULL )
    return(NULL);
  *errp = 0;			/* assume success */
  if ( fn == NULL || fn[0] == 0 || lnp == NULL )
    {
      *errp = ERR_SCM_INVALARG;
      return(NULL);
    }
  fin = fopen(fn, "r");
  if ( fin == NULL )
    {
      *errp = ERR_SCM_COFILE;
      return(NULL);
    }
  scmp = (scm *)calloc(1, sizeof(scm));
  if ( scmp == NULL )
    {
      (void)fclose(fin);
      *errp = ERR_SCM_NOMEM;
      return(NULL);
    }
  *errp = handlescmfile(scmp, fin, lnp);
  (void)fclose(fin);
  if ( *errp != 0 )
    {
      freescm(scmp);
      scmp = NULL;
    }
  return(scmp);
}

#ifdef TEST

int main(int argc, char **argv)
{
  scm *scmp;
  int  err = 0;
  int  lno = 0;

  scmp = parsescm(argv[1], &err, &lno);
  if ( scmp != NULL )
    (void)printf("parsescm(%s) ok, DSN = %s\n",
		 argv[1], scmp->dsn);
  else
    (void)printf("parsescm(%s) failed with err %d on line %d\n",
		 argv[1], err, lno);
  return(err);
}

#endif
