/*
  $Id$
*/

#ifndef _SCMF_H_
#define _SCMF_H_

#include <sql.h>
#include <sqlext.h>

typedef struct _scmstat
{
  char     *errmsg;		/* error messages */
  char     *tabname;            /* name of table having error: not allocated */
  int       emlen;		/* alloc'd length of errmsg */
  int       rows;		/* rows changed */
} scmstat;

typedef struct _scmcon
{
  SQLHENV   henv;		/* environment handle */
  SQLHDBC   hdbc;		/* database handle */
  SQLHSTMT  hstmt;		/* statement handle */
  int       connected;		/* are we connected? */
  scmstat   mystat;		/* statistics and errors */
} scmcon;

typedef struct _scmkv
{
  char     *column;		/* column name */
  char     *value;		/* value for that column */
} scmkv ;

typedef struct _scmkva
{
  scmkv    *vec;		/* array of column/value pairs */
  int       ntot;		/* total length of "vec" */
  int       nused;		/* number of elements of "vec" in use */
} scmkva;

#ifndef SQLOK
#define SQLOK(s) (s == SQL_SUCCESS || s == SQL_SUCCESS_WITH_INFO)
#endif

extern scmcon *connectscm(char *dsnp, char *errmsg, int emlen);
extern void    disconnectscm(scmcon *conp);
extern char   *geterrorscm(scmcon *conp);
extern char   *gettablescm(scmcon *conp);
extern int     getrowsscm(scmcon *conp);
extern int     statementscm(scmcon *conp, char *stm);
extern int     createdbscm(scmcon *conp, char *dbname, char *dbuser);
extern int     deletedbscm(scmcon *conp, char *dbname);
extern int     createalltablesscm(scmcon *conp, scm *scmp);
extern int     insertscm(scmcon *conp, scmtab *tabp, scmkva *arr, int vald);

/*
  Error codes
*/

#define ERR_SCM_NOERR         0
#define ERR_SCM_COFILE       -1  	/* cannot open file */
#define ERR_SCM_NOMEM        -2	        /* out of memory */
#define ERR_SCM_INVALARG     -3	        /* invalid argument */
#define ERR_SCM_SQL          -4         /* SQL error */
#define ERR_SCM_INVALCOL     -5	        /* invalid column */
#define ERR_SCM_NULLCOL      -6         /* null column */

#endif
