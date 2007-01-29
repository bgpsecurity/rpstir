/*
  $Id$
*/

#ifndef _SCM_H_
#define _SCM_H_

typedef struct _scmtab
{
  char  *tabname;		/* SQL name of table */
  char  *hname;			/* human readable name of table */
  char  *tstr;			/* table creation string */
  char **cols;			/* array of column names */
  int    ncols;			/* number of columns in "cols" */
} scmtab;

typedef struct _scm
{
  char   *dsn;			/* canonical data source name from .dsn section */
  scmtab *tables;		/* array of tables */
  int     ntables;		/* number of tables in "tables" */
} scm;

/*
  Error codes
*/

#endif
