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

#define ERR_SCM_NOERR         0
#define ERR_SCM_COFILE       -1  	/* cannot open file */
#define ERR_SCM_NOMEM        -2	        /* out of memory */
#define ERR_SCM_INVALARG     -3	        /* invalid argument */
#define ERR_SCM_NODSN        -4	        /* no DSN specified */
#define ERR_SCM_NODIR        -5         /* missing directive */
#define ERR_SCM_INVALDIR     -6         /* invalid directive */
#define ERR_SCM_XMOD         -7         /* extra modifiers */
#define ERR_SCM_NOMOD        -8         /* missing modifier */
#define ERR_SCM_INVALMOD     -9         /* invalid modifier */
#define ERR_SCM_NXEOF       -10         /* unexpected EOF */
#define ERR_SCM_NXDIR       -11	        /* unexpected end of directive */
#define ERR_SCM_NXSDIR      -12         /* unexpected end of subdirective */
#define ERR_SCM_INVALSDIR   -13         /* invalid subdirective */

/*
  Directives
*/

#define SCM_DIR_DSN           1          /* DSN directive */
#define SCM_DIR_TABLES        2          /* TABLES directive */

#endif
