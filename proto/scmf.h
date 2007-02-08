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

/*
  Error codes
*/

#define ERR_SCM_NOERR         0
#define ERR_SCM_COFILE       -1  	/* cannot open file */
#define ERR_SCM_NOMEM        -2	        /* out of memory */
#define ERR_SCM_INVALARG     -3	        /* invalid argument */
#define ERR_SCM_SQL          -4         /* SQL error */

#endif
