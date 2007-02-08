/*
  $Id$
*/

#ifndef _SCM_H_
#define _SCM_H_

/*
  A database table has four characteristics: its real name (the name
  by which the database knows it), its user-friendly name, the
  SQL statement that queries it, and the list of column names.
  The following data structure captures that.
*/

typedef struct _scmtab
{
  char  *tabname;		/* SQL name of table */
  char  *hname;			/* human readable name of table */
  char  *tstr;			/* table creation string */
  char **cols;			/* array of column names */
  int    ncols;			/* number of columns in "cols" */
} scmtab;

/*
  This structure defines the overall database schema
*/

typedef struct _scm
{
  char   *db;                   /* name of the database */
  char   *dbuser;               /* name of the database user */
  char   *dsnpref;              /* data source name prefix */
  char   *dsn;			/* canonical data source name */
  scmtab *tables;		/* array of tables */
  int     ntables;		/* number of tables in "tables" */
} scm;

extern scm  *initscm(void);
extern void  freescm(scm *scmp);
extern char *makedsnscm(char *pref, char *db, char *usr, char *pass);

#endif
