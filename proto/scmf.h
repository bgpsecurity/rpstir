/*
  $Id$
*/

#ifndef _SCMF_H_
#define _SCMF_H_

#include <sql.h>
#include <sqlext.h>

typedef struct _scmcon
{
  SQLHENV   henv;		/* environment handle */
  SQLHDBC   hdbc;		/* database handle */
  SQLHSTMT  hstmt;		/* statement handle */
  int       connected;		/* are we connected? */
} scmcon;

#ifndef SQLOK
#define SQLOK(s) (s == SQL_SUCCESS || s == SQL_SUCCESS_WITH_INFO)
#endif

extern scmcon *connectscm(char *dsnp, char *errmsg, int emlen);
extern void    disconnectscm(scmcon *conp);

#endif
