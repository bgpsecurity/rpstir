/*
  $Id$
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "scm.h"
#include "scmf.h"
#include "err.h"

/*
  Decode the last error on a handle
*/

static void heer(void *h, int what, char *errmsg, int emlen)
{
  SQLINTEGER  nep;
  SQLSMALLINT tl;
  char state[24];

  SQLGetDiagRec(what, h, 1, (SQLCHAR *)&state[0], &nep,
                (SQLCHAR *)errmsg, emlen, &tl);
}

/*
  Disconnect from a DSN and free all memory.
*/

void disconnectscm(scmcon *conp)
{
  if ( conp == NULL )
    return;
  if ( conp->hstmt != NULL )
    {
      SQLFreeHandle(SQL_HANDLE_STMT, conp->hstmt);
      conp->hstmt = NULL;
    }
  if ( conp->connected > 0 )
    {
      SQLDisconnect(conp->hdbc);
      conp->connected = 0;
    }
  if ( conp->hdbc != NULL )
    {
      SQLFreeHandle(SQL_HANDLE_DBC, conp->hdbc);
      conp->hdbc = NULL;
    }
  if ( conp->henv != NULL )
    {
      SQLFreeHandle(SQL_HANDLE_ENV, conp->henv);
      conp->henv = NULL;
    }
  if ( conp->mystat.errmsg != NULL )
    {
      free((void *)(conp->mystat.errmsg));
      conp->mystat.errmsg = NULL;
    }
  free((void *)conp);
}

/*
  Initialize a connection to the named DSN. Return a connection object on
  success and a negative error code on failure.
*/

scmcon *connectscm(char *dsnp, char *errmsg, int emlen)
{
  SQLSMALLINT inret;
  SQLSMALLINT outret;
  static char nulldsn[] = "NULL DSN";
  static char badhenv[] = "Cannot allocate HENV handle";
  static char oom[] = "Out of memory!";
  scmcon     *conp;
  SQLRETURN   ret;
  char outlen[1024];

  if ( errmsg != NULL && emlen > 0 )
    memset(errmsg, 0, emlen);
  if ( dsnp == NULL || dsnp[0] == 0 )
    {
      if ( errmsg != NULL && (unsigned)emlen > strlen(nulldsn) )
	(void)strcpy(errmsg, nulldsn);
      return(NULL);
    }
  conp = (scmcon *)calloc(1, sizeof(scmcon));
  if ( conp == NULL )
    {
      if ( errmsg != NULL && (unsigned)emlen > strlen(oom) )
	(void)strcpy(errmsg, oom);
      return(NULL);
    }
  conp->mystat.errmsg = (char *)calloc(1024, sizeof(char));
  if ( conp->mystat.errmsg == NULL )
    {
      if ( errmsg != NULL && (unsigned)emlen > strlen(oom) )
	(void)strcpy(errmsg, oom);
      free((void *)conp);
      return(NULL);
    }
  conp->mystat.emlen = 1024;
  ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &conp->henv);
  if ( ! SQLOK(ret) )
    {
      disconnectscm(conp);
      if ( errmsg != NULL && (unsigned)emlen > strlen(badhenv) )
	(void)strcpy(errmsg, badhenv);
      return(NULL);
    }
  ret = SQLSetEnvAttr(conp->henv, SQL_ATTR_ODBC_VERSION,
		      (SQLPOINTER)SQL_OV_ODBC3, sizeof(int));
  if ( ! SQLOK(ret) )
    {
      if ( errmsg != NULL && emlen > 0 )
	heer((void *)conp->henv, SQL_HANDLE_ENV, errmsg, emlen);
      disconnectscm(conp);
      return(NULL);
    }
  ret = SQLAllocHandle(SQL_HANDLE_DBC, conp->henv, &conp->hdbc);
  if ( ! SQLOK(ret) )
    {
      if ( errmsg != NULL && emlen > 0 )
	heer((void *)conp->henv, SQL_HANDLE_ENV, errmsg, emlen);
      disconnectscm(conp);
      return(NULL);
    }
  inret = strlen(dsnp);
  ret = SQLDriverConnect(conp->hdbc, NULL, (SQLCHAR *)dsnp, inret,
			 (SQLCHAR *)&outlen[0], 1024, &outret, 0);
  if ( !SQLOK(ret) )
    {
      if ( errmsg != NULL && emlen > 0 )
	heer((void *)conp->hdbc, SQL_HANDLE_DBC, errmsg, emlen);
      disconnectscm(conp);
      return(NULL);
    }
  conp->connected++;
  ret = SQLAllocHandle(SQL_HANDLE_STMT, conp->hdbc, &conp->hstmt);
  if ( ! SQLOK(ret) )
    {
      if ( errmsg != NULL && emlen > 0 )
	heer((void *)conp->hdbc, SQL_HANDLE_DBC, errmsg, emlen);
      disconnectscm(conp);
      return(NULL);
    }
  ret = SQLSetStmtAttr(conp->hstmt, SQL_ATTR_NOSCAN,
		       (SQLPOINTER)SQL_NOSCAN_ON,
		       SQL_IS_UINTEGER);
  if ( ! SQLOK(ret) )
    {
      if ( errmsg != NULL && emlen > 0 )
	heer((void *)conp->hstmt, SQL_HANDLE_STMT, errmsg, emlen);
      disconnectscm(conp);
      return(NULL);
    }
  return(conp);
}

/*
  Get the error message from a connection.
*/

char *geterrorscm(scmcon *conp)
{
  if ( conp == NULL || conp->mystat.errmsg == NULL )
    return(NULL);
  return(conp->mystat.errmsg);
}

/*
  Get the name of the table that had an error.
*/

char *gettablescm(scmcon *conp)
{
  if ( conp == NULL )
    return(NULL);
  return(conp->mystat.tabname);
}


/*
  Get the number of rows returned by a statement.
*/

int getrowsscm(scmcon *conp)
{
  int r;

  if ( conp == NULL )
    return(ERR_SCM_INVALARG);
  r = conp->mystat.rows;
  return(r);
}

/*
  Execute an SQL statement.
*/

int statementscm(scmcon *conp, char *stm)
{
  SQLINTEGER istm;
  SQLRETURN  ret;

  if ( conp == NULL || conp->connected == 0 || stm == NULL ||
       stm[0] == 0 )
    return(ERR_SCM_INVALARG);
  memset(conp->mystat.errmsg, 0, conp->mystat.emlen);
  istm = strlen(stm);
  ret = SQLExecDirect(conp->hstmt, (SQLCHAR *)stm, istm);
  if ( ! SQLOK(ret) )
    {
      heer((void *)(conp->hstmt), SQL_HANDLE_STMT, conp->mystat.errmsg,
	   conp->mystat.emlen);
      return(ERR_SCM_SQL);
    }
  istm = 0;
  ret = SQLRowCount(conp->hstmt, &istm);
  if ( ! SQLOK(ret) )
    {
      heer((void *)(conp->hstmt), SQL_HANDLE_STMT, conp->mystat.errmsg,
	   conp->mystat.emlen);
      return(ERR_SCM_SQL);
    }
  return(0);
}

/*
  Create a database and grant the mysql default user the standard
  set of privileges for that database.
*/

int createdbscm(scmcon *conp, char *dbname, char *dbuser)
{
  char *mk;
  int   sta;

  if ( dbname == NULL || dbname[0] == 0 || conp == NULL ||
       conp->connected == 0 || dbuser == NULL || dbuser[0] == 0 )
    return(ERR_SCM_INVALARG);
  mk = (char *)calloc(strlen(dbname) + strlen(dbuser) + 130, sizeof(char));
  if ( mk == NULL )
    return(ERR_SCM_NOMEM);
  (void)sprintf(mk, "CREATE DATABASE %s;", dbname);
  sta = statementscm(conp, mk);
  if ( sta < 0 )
    {
      free((void *)mk);
      return(sta);
    }
  (void)sprintf(mk,
    "GRANT DELETE, INSERT, LOCK TABLES, SELECT, UPDATE ON %s.* TO '%s'@'localhost';",
    dbname, dbuser);
  sta = statementscm(conp, mk);
  free((void *)mk);
  return(sta);
}

/*
  Delete a database.
*/

int deletedbscm(scmcon *conp, char *dbname)
{
  char *mk;
  int   sta;

  if ( dbname == NULL || dbname[0] == 0 || conp == NULL ||
       conp->connected == 0 )
    return(ERR_SCM_INVALARG);
  mk = (char *)calloc(strlen(dbname) + 30, sizeof(char));
  if ( mk == NULL )
    return(ERR_SCM_NOMEM);
  (void)sprintf(mk, "DROP DATABASE IF EXISTS %s;", dbname);
  sta = statementscm(conp, mk);
  free((void *)mk);
  return(sta);
}

/*
  Create a single table.
*/

static int createonetablescm(scmcon *conp, scmtab *tabp)
{
  char *mk;
  int   sta;

  if ( tabp->tstr == NULL || tabp->tstr[0] == 0 )
    return(0);			/* no op */
  conp->mystat.tabname = tabp->hname;
  mk = (char *)calloc(strlen(tabp->tabname) + strlen(tabp->tstr) + 100,
		      sizeof(char));
  if ( mk == NULL )
    return(ERR_SCM_NOMEM);
  (void)sprintf(mk, "CREATE TABLE %s ( %s );", tabp->tabname, tabp->tstr);
  sta = statementscm(conp, mk);
  free((void *)mk);
  return(sta);
}

/*
  Create all the tables listed in scmp. This assumes that the database
  has already been created through a call to createdbscm().
*/

int createalltablesscm(scmcon *conp, scm *scmp)
{
  char *mk;
  int   sta = 0;
  int   i;

  if ( conp == NULL || conp->connected == 0 || scmp == NULL )
    return(ERR_SCM_INVALARG);
  if ( scmp->ntables > 0 && scmp->tables == NULL )
    return(ERR_SCM_INVALARG);
  mk = (char *)calloc(strlen(scmp->db) + 30, sizeof(char));
  if ( mk == NULL )
    return(ERR_SCM_NOMEM);
  (void)sprintf(mk, "USE %s;", scmp->db);
  sta = statementscm(conp, mk);
  if ( sta < 0 )
    return(sta);
  for(i=0;i<scmp->ntables;i++)
    {
      sta = createonetablescm(conp, &scmp->tables[i]);
      if ( sta < 0 )
	break;
    }
  return(sta);
}

/*
  Return the index of the named column in the given schema table,
  or a negative error code on failure.
*/

static int findcol(scmtab *tabp, char *coln)
{
  char *ptr;
  int   i;

  if ( tabp == NULL || coln == NULL || coln[0] == 0 )
    return(-1);
  if ( tabp->cols == NULL || tabp->ncols <= 0 )
    return(-2);
  for(i=0;i<tabp->ncols;i++)
    {
      ptr = tabp->cols[i];
      if ( ptr != NULL && ptr[0] != 0 && strcasecmp(ptr, coln) == 0 )
	return(i);
    }
  return(-3);
}

/*
  Validate that each of the columns mentioned actually occurs
  in the indicated table. Return 0 on success and a negative
  error code on failure.
*/

static int valcols(scmcon *conp, scmtab *tabp, scmkva *arr)
{
  char *ptr;
  int   i;

  if ( conp == NULL || tabp == NULL || arr == NULL || arr->vec == NULL )
    return(ERR_SCM_INVALARG);
  for(i=0;i<arr->nused;i++)
    {
      ptr = arr->vec[i].column;
      if ( ptr == NULL || ptr[0] == 0 )
	return(ERR_SCM_NULLCOL);
      if ( findcol(tabp, ptr) < 0 )
	{
	  if ( conp->mystat.errmsg != NULL )
	    (void)sprintf(conp->mystat.errmsg, "Invalid column %s", ptr);
	  return(ERR_SCM_INVALCOL);
	}
    }
  return(0);
}

/*
  Insert an entry into a database table.
*/

int insertscm(scmcon *conp, scmtab *tabp, scmkva *arr)
{
  char *stmt;
  int   sta;
  int   leen = 128;
  int   doq;
  int   i;

  if ( conp == NULL || conp->connected == 0 || tabp == NULL ||
       tabp->tabname == NULL )
    return(ERR_SCM_INVALARG);
  conp->mystat.tabname = tabp->hname;
// handle the trivial cases first
  if ( arr == NULL || arr->nused <= 0 || arr->vec == NULL )
    return(0);
// if the columns listed in arr have not already been validated
// against the set of columns present in the table, then do so
  if ( arr->vald == 0 )
    {
      sta = valcols(conp, tabp, arr);
      if ( sta < 0 )
	return(sta);
      arr->vald = 1;
    }
// glean the length of the statement
  leen += strlen(tabp->tabname);
  for(i=0;i<arr->nused;i++)
    {
      leen += strlen(arr->vec[i].column) + 2;
      leen += strlen(arr->vec[i].value) + 4;
    }
// construct the statement
  stmt = (char *)calloc(leen, sizeof(char));
  if ( stmt == NULL )
    return(ERR_SCM_NOMEM);
  (void)sprintf(stmt, "INSERT INTO %s (%s", tabp->tabname,
		arr->vec[0].column);
  for(i=1;i<arr->nused;i++)
    {
      (void)strcat(stmt, ", ");
      (void)strcat(stmt, arr->vec[i].column);
    }
/*
  Note the special convention that if the value (as a string)
  begins with 0x it is NOT quoted. This is so that we can insert
  binary strings in their hex representation. Thus if we said
  0x00656667 as the value it would get inserted as NULefg but
  if we said "0x00656667" it would get inserted as the string
  0x00656667.
*/
  doq = strncmp(arr->vec[0].value, "0x", 2);
  if ( doq == 0 )
    (void)strcat(stmt, ") VALUES (");
  else
    (void)strcat(stmt, ") VALUES (\"");
  (void)strcat(stmt, arr->vec[0].value);
  if ( doq != 0 )
    (void)strcat(stmt, "\"");
  for(i=1;i<arr->nused;i++)
    {
      doq = strncmp(arr->vec[i].value, "0x", 2);
      if ( doq == 0 )
	(void)strcat(stmt, ", ");
      else
	(void)strcat(stmt, ", \"");
      (void)strcat(stmt, arr->vec[i].value);
      if ( doq != 0 )
	(void)strcat(stmt, "\"");
    }
  (void)strcat(stmt, ");");
  sta = statementscm(conp, stmt);
  free((void *)stmt);
  return(sta);
}

int getuintscm(scmcon *conp, unsigned int *ival)
{
  SQLUINTEGER f1;
  SQLINTEGER  f1len;
  SQLRETURN   rc;
  int fnd = 0;

  if ( conp == NULL || conp->connected == 0 || ival == NULL )
    return(ERR_SCM_INVALARG);
  SQLBindCol(conp->hstmt, 1, SQL_C_ULONG, &f1, sizeof(f1), &f1len);
  while ( 1 )
    {
      rc = SQLFetch(conp->hstmt);
      if ( rc == SQL_NO_DATA )
	break;
      if ( !SQLOK(rc) )
	continue;
      if ( f1len == SQL_NO_DATA )
	continue;
      fnd++;
      *ival = (unsigned int)f1;
    }
  SQLCloseCursor(conp->hstmt);
  if ( fnd == 0 )
    return(ERR_SCM_NODATA);
  else
    return(0);
}

/*
  Get the maximum id of the table known as "what". A name translation
  takes place as follows: what is looked up as the human name of the table;
  the real name is then obtained; the prefix is then removed. So, for example,
  for the "DIRECTORY" table, the real name is apki_dir. Removing the prefix
  ("apki" + "_") yields "dir", so that actual column name is dir_max in the
  METADATA table.

  Note that as an optimization the pointer to the metadata table "mtab"
  may be provided.  If it is null it is looked up.
*/

int getmaxidscm(scm *scmp, scmcon *conp, scmtab *mtab, char *what,
		unsigned int *ival)
{
  scmtab *otab;
  char   *stmt;
  char   *ptr;
  char   *speccol;
  int     leen;
  int     sta;

  if ( scmp == NULL || conp == NULL || conp->connected == 0 || what == NULL ||
       what[0] == 0 || ival == NULL )
    return(ERR_SCM_INVALARG);
  if ( mtab == NULL )
    {
      mtab = findtablescm(scmp, "METADATA");
      if ( mtab == NULL )
	{
	  conp->mystat.tabname = "METADATA";
	  if ( conp->mystat.errmsg != NULL )
	    (void)strcpy(conp->mystat.errmsg, "Cannot find METADATA table");
	  return(ERR_SCM_NOSUCHTAB);
	}
    }
/*
  The name of the special column in the metadata table, which will always
  be the last column.
*/
  speccol = mtab->cols[mtab->ncols-1];
  otab = findtablescm(scmp, what);
  if ( otab == NULL )
    {
      if ( conp->mystat.errmsg != NULL )
	(void)sprintf(conp->mystat.errmsg, "Cannot find %s table", what);
      return(ERR_SCM_NOSUCHTAB);
    }
  ptr = otab->tabname;
  if ( strncasecmp(ptr, scmp->db, strlen(scmp->db)) == 0 )
    ptr += strlen(scmp->db);
  if ( *ptr == '_' )
    ptr++;
  leen = strlen(ptr) + strlen(mtab->tabname) + strlen(speccol) + 64;
  stmt = (char *)calloc(leen, sizeof(char));
  if ( stmt == NULL )
    return(ERR_SCM_NOMEM);
  (void)sprintf(stmt, "SELECT %s_max FROM %s WHERE %s=1;",
		ptr, mtab->tabname, speccol);
  sta = statementscm(conp, stmt);
  free((void *)stmt);
  if ( sta < 0 )
    return(sta);
  sta = getuintscm(conp, ival);
  return(sta);
}

/*
  Set the maximum id of the table known as "what". A name translation
  takes place as described in the previous function.

  Note that as an optimization the pointer to the metadata table "mtab"
  may be provided.  If it is null it is looked up.
*/

int setmaxidscm(scm *scmp, scmcon *conp, scmtab *mtab, char *what,
		unsigned int ival)
{
  scmtab *otab;
  char   *stmt;
  char   *ptr;
  char   *speccol;
  int     leen;
  int     sta;

  if ( scmp == NULL || conp == NULL || conp->connected == 0 || what == NULL ||
       what[0] == 0 )
    return(ERR_SCM_INVALARG);
  if ( mtab == NULL )
    {
      mtab = findtablescm(scmp, "METADATA");
      if ( mtab == NULL )
	{
	  conp->mystat.tabname = "METADATA";
	  if ( conp->mystat.errmsg != NULL )
	    (void)strcpy(conp->mystat.errmsg, "Cannot find METADATA table");
	  return(ERR_SCM_NOSUCHTAB);
	}
    }
/*
  The name of the special column in the metadata table, which will always
  be the last column.
*/
  speccol = mtab->cols[mtab->ncols-1];
  otab = findtablescm(scmp, what);
  if ( otab == NULL )
    {
      if ( conp->mystat.errmsg != NULL )
	(void)sprintf(conp->mystat.errmsg, "Cannot find %s table", what);
      return(ERR_SCM_NOSUCHTAB);
    }
  ptr = otab->tabname;
  if ( strncasecmp(ptr, scmp->db, strlen(scmp->db)) == 0 )
    ptr += strlen(scmp->db);
  if ( *ptr == '_' )
    ptr++;
  leen = strlen(ptr) + strlen(mtab->tabname) + strlen(speccol) + 64;
  stmt = (char *)calloc(leen, sizeof(char));
  if ( stmt == NULL )
    return(ERR_SCM_NOMEM);
  (void)sprintf(stmt, "UPDATE %s SET %s_max=%u WHERE %s=1;",
		mtab->tabname, ptr, ival, speccol);
  sta = statementscm(conp, stmt);
  free((void *)stmt);
  return(sta);
}

/*
  Validate a search array struct
*/

static int validsrchscm(scmcon *conp, scmtab *tabp, scmsrcha *srch)
{
  scmsrch *vecp;
  int sta;
  int i;

  if ( srch == NULL || srch->vec == NULL || srch->nused <= 0 )
    return(ERR_SCM_INVALARG);
  for(i=0;i<srch->nused;i++)
    {
      vecp = (&srch->vec[i]);
      if ( vecp->colname == NULL || vecp->colname[0] == 0 )
	return(ERR_SCM_NULLCOL);
      if ( vecp->valptr == NULL )
	return(ERR_SCM_NULLVALP);
      if ( vecp->valsize == 0 )
	return(ERR_SCM_INVALSZ);
    }
  if ( srch->where != NULL && srch->where->vald == 0 )
    {
      sta = valcols(conp, tabp, srch->where);
      if ( sta < 0 )
	return(sta);
      srch->where->vald = 1;
    }
  return(0);
}

/*
  This function searches in a database table for entries that match
  the stated search criteria.
*/

int searchscm(scmcon *conp, scmtab *tabp, scmsrcha *srch,
	      sqlcountfunc cnter, sqlvaluefunc valer,
	      int what)
{
  SQLINTEGER  nrows = 0;
  SQLRETURN   rc;
  scmsrch    *vecp;
  char *stmt = NULL;
  int   docall;
  int   leen = 100;
  int   sta = 0;
  int   nfnd = 0;
  int   bset = 0;
  int   ridx = 0;
  int   nok = 0;
  int   didw = 0;
  int   fnd;
  int   i;

// validate arguments
  if ( conp == NULL || conp->connected == 0 || tabp == NULL ||
       tabp->tabname == NULL )
    return(ERR_SCM_INVALARG);
  if ( srch->vald == 0 )
    {
      sta = validsrchscm(conp, tabp, srch);
      if ( sta < 0 )
	return(sta);
      srch->vald = 1;
    }
  if ( (what & SCM_SRCH_DOVALUE) )
    {
      if ( (what & SCM_SRCH_DOVALUE_ANN) )
	bset++;
      if ( (what & SCM_SRCH_DOVALUE_SNN) )
	bset++;
      if ( (what & SCM_SRCH_DOVALUE_ALWAYS) )
	bset++;
      if ( bset > 1 )
	return(ERR_SCM_INVALARG);
    }
// construct the SELECT statement
  conp->mystat.tabname = tabp->hname;
  leen += strlen(tabp->tabname);
  for(i=0;i<srch->nused;i++)
    leen += strlen(srch->vec[i].colname) + 2;
  if ( srch->where != NULL )
    {
      for(i=0;i<srch->where->nused;i++)
	{
	  leen += strlen(srch->where->vec[i].column) + 9;
	  leen += strlen(srch->where->vec[i].value);
	}
    }
  if ( srch->wherestr != NULL )
    leen += strlen(srch->wherestr) + 24;
  if ( (what & SCM_SRCH_DO_JOIN) )
    leen += strlen(tabp->tabname) + 48;
  stmt = (char *)calloc(leen, sizeof(char));
  if ( stmt == NULL )
    return(ERR_SCM_NOMEM);
  (void)sprintf(stmt, "SELECT %s", srch->vec[0].colname);
  for(i=1;i<srch->nused;i++)
    {
      (void)strcat(stmt, ", ");
      (void)strcat(stmt, srch->vec[i].colname);
    }
  (void)strcat(stmt, " FROM ");
  (void)strcat(stmt, tabp->tabname);
// put in the join if requested
  if ( (what & SCM_SRCH_DO_JOIN) )
    {
      (void)strcat(stmt, " LEFT JOIN apki_dir on ");
      (void)strcat(stmt, tabp->tabname);
      (void)strcat(stmt, ".dir_id = apki_dir.dir_id");
    }
  if ( srch->where != NULL )
    {
      didw++;
      (void)strcat(stmt, " WHERE ");
      (void)strcat(stmt, srch->where->vec[0].column);
      (void)strcat(stmt, "=\"");
      (void)strcat(stmt, srch->where->vec[0].value);
      (void)strcat(stmt, "\"");
      for(i=1;i<srch->where->nused;i++)
	{
	  (void)strcat(stmt, " AND ");
	  (void)strcat(stmt, srch->where->vec[i].column);
	  (void)strcat(stmt, "=\"");
	  (void)strcat(stmt, srch->where->vec[i].value);
	  (void)strcat(stmt, "\"");
	}
    }
  if ( srch->wherestr != NULL )
    {
      if ( didw == 0 )
	(void)strcat(stmt, " WHERE ");
      else
	(void)strcat(stmt, " AND ");
      (void)strcat(stmt, srch->wherestr);
    }
  (void)strcat(stmt, ";");
// execute the select statement
  sta = statementscm(conp, stmt);
  free((void *)stmt);
  if ( sta < 0 )
    {
      SQLCloseCursor(conp->hstmt);
      return(sta);
    }
// count rows and call counter function if requested
  if ( (what & SCM_SRCH_DOCOUNT) && cnter != NULL )
    {
      rc = SQLRowCount(conp->hstmt, &nrows);
      if ( !SQLOK(rc) && (what & SCM_SRCH_BREAK_CERR) )
	{
	  heer((void *)(conp->hstmt), SQL_HANDLE_STMT, conp->mystat.errmsg,
	       conp->mystat.emlen);
	  SQLCloseCursor(conp->hstmt);
	  return(ERR_SCM_SQL);
	}
      sta = (*cnter)(conp, srch, (int)nrows);
      if ( sta < 0 && (what & SCM_SRCH_BREAK_CERR) )
	{
	  SQLCloseCursor(conp->hstmt);
	  return(sta);
	}
    }
// loop over the results calling the value callback if requested
  if ( (what & SCM_SRCH_DOVALUE) && valer != NULL )
    {
// do the column binding
      for(i=0;i<srch->nused;i++)
	{
	  vecp = (&srch->vec[i]);
	  SQLBindCol(conp->hstmt, vecp->colno <= 0 ? i+1 : vecp->colno,
		     vecp->sqltype, vecp->valptr, vecp->valsize,
		     (SQLINTEGER *)&vecp->avalsize);
	}
      while ( 1 )
	{
	  ridx++;
	  rc = SQLFetch(conp->hstmt);
	  if ( rc == SQL_NO_DATA )
	    break;
	  if ( !SQLOK(rc) )
	    {
	      nok++;
	      if ( nok >= 2 )
		break;
	      else
		continue;
	    }
// count how many columns actually contain data
	  fnd = 0;
	  for(i=0;i<srch->nused;i++)
	    {
	      if ( srch->vec[i].avalsize != SQL_NO_DATA )
		fnd++;
	    }
	  if ( fnd == 0 )
	    continue;
	  nfnd++;
// determine if the function should be called and call it if so
// we have already validated that only one of these bits is set
	  docall = 0;
	  if ( (what & SCM_SRCH_DOVALUE_ALWAYS) )
	    docall++;
	  if ( (what & SCM_SRCH_DOVALUE_SNN) && (fnd > 0) )
	    docall++;
	  if ( (what & SCM_SRCH_DOVALUE_ANN) && (fnd == srch->nused) )
	    docall++;
	  if ( docall > 0 )
	    {
	      sta = (valer)(conp, srch, ridx);
	      if ( (sta < 0) && (what & SCM_SRCH_BREAK_VERR) )
		break;
	    }
	}
    }
  SQLCloseCursor(conp->hstmt);
  if ( sta < 0 )
    return(sta);
  if ( nfnd == 0 )
    return(ERR_SCM_NODATA);
  else
    return(0);
}

/*
  Free all the memory in a search array
*/

void freesrchscm(scmsrcha *srch)
{
  scmsrch *vecp;
  int i;

  if ( srch != NULL )
    {
      if ( srch->sname != NULL )
	{
	  free((void *)(srch->sname));
	  srch->sname = NULL;
	}
      if ( srch->context != NULL )
	{
	  free(srch->context);
	  srch->context = NULL;
	}
      if ( srch->wherestr != NULL )
	{
	  free(srch->wherestr);
	  srch->wherestr = NULL;
	}
      if ( srch->vec != NULL )
	{
	  for(i=0;i<srch->nused;i++)
	    {
	      vecp = &srch->vec[i];
	      if ( vecp->colname != NULL )
		{
		  free((void *)(vecp->colname));
		  vecp->colname = NULL;
		}
	      if ( vecp->valptr != NULL )
		{
		  free((void *)(vecp->valptr));
		  vecp->valptr = NULL;
		}
	    }
	  free((void *)(srch->vec));
	}
      free((void *)srch);
    }
}

/*
  Create a new empty srch array
*/

scmsrcha *newsrchscm(char *name, int leen, int cleen)
{
  scmsrcha *newp;

  if ( leen <= 0 )
    return(NULL);
  newp = (scmsrcha *)calloc(1, sizeof(scmsrcha));
  if ( newp == NULL )
    return(NULL);
  if ( name != NULL && name[0] != 0 )
    {
      newp->sname = strdup(name);
      if ( newp->sname == NULL )
	{
	  freesrchscm(newp);
	  return(NULL);
	}
    }
  newp->vec = (scmsrch *)calloc(leen, sizeof(scmsrch));
  if ( newp->vec == NULL )
    {
      freesrchscm(newp);
      return(NULL);
    }
  if ( cleen <= 0 )
    cleen = sizeof(unsigned int);
  newp->context = (void *)calloc(cleen, sizeof(char));
  if ( newp->context == NULL )
    {
      freesrchscm(newp);
      return(NULL);
    }
  newp->ntot = leen;
  return(newp);
}

/*
  Add a new column to a search array. Note that this function does
  not grow the size of the column array, so enough space must have
  already been allocated when the array was created.
*/

int addcolsrchscm(scmsrcha *srch, char *colname, int sqltype, unsigned valsize)
{
  scmsrch *vecp;
  char *cdup;
  void *v;

  if ( srch == NULL || srch->vec == NULL || srch->ntot <= 0 ||
       colname == NULL || colname[0] == 0 || valsize == 0 )
    return(ERR_SCM_INVALARG);
  if ( srch->nused >= srch->ntot )
    return(ERR_SCM_INVALSZ);
  cdup = strdup(colname);
  if ( cdup == NULL )
    return(ERR_SCM_NOMEM);
  v = (void *)calloc(1, valsize);
  if ( v == NULL )
    return(ERR_SCM_NOMEM);
  vecp = &srch->vec[srch->nused];
  vecp->colno = srch->nused + 1;
  vecp->sqltype = sqltype;
  vecp->colname = cdup;
  vecp->valptr = v;
  vecp->valsize = valsize;
  srch->nused++;
  return(0);
}

/*
  This is the value function callback for the next function.
*/

static int socvaluefunc(scmcon *conp, scmsrcha *s, int idx)
{
  UNREFERENCED_PARAMETER(conp);
  UNREFERENCED_PARAMETER(idx);
  if ( s->vec[0].sqltype == SQL_C_ULONG &&
       (unsigned)(s->vec[0].avalsize) >= sizeof(unsigned int) &&
       s->context != NULL )
    {
      memcpy(s->context, s->vec[0].valptr, sizeof(unsigned int));
      return(0);
    }
  return(-1);
}

/*
  This function performs a find-or-create operation for a specific id. It first
  searches in table "tab" with search criteria "srch". If the entry is found it
  returns the value of the id. If it isn't found then the max_id is looked up in
  the metadata table and incremented, a new entry is created in "tab" using the
  creation criteria "ins", and the max id in the metadata table is updated and
  returned.

  Since this is somewhat convoluted and contains several steps, consider
  an example.  Suppose I wish to find or create two directories in the
  directory table.  These directories are /path/to/somewhere and
  /path/to/elsewhere.  I want to get the directory ids for these directories
  in either case, e.g. whether they are already there or have to be
  created. If a new directory is created I also want the maximum directory
  id in the metadata table to be updated.

  Consider the following putative sequence.  I construct a search
  for "/path/to/somewhere" in the directory table. The first element
  of the search is the id. The search succeeds, and the id is returned.
  The metadata table is unchanged. Now I construct a second search for
  "/path/to/elsewhere". That search fails. So I fetch the maximum directory
  id from the metadata table and increment it. I then create an entry
  in the directory table with elements "/path/to/elsewhere" and that
  (incremented) id. I update the metadata table's value for the max
  directory id to the new, incremented id, and, finally, I return that
  new, incremented id.

  Certs, CRLs, ROAs and directories all have ids and their tables all
  have max ids in the metadata table and so all of them have to be
  managed using this (sadly prolix) function.
*/

int searchorcreatescm(scm *scmp, scmcon *conp, scmtab *tabp, scmtab *mtab,
		      scmsrcha *srch, scmkva *ins, unsigned int *idp)
{
  unsigned int mid;
  char *tmp;
  int   sta;

  if ( idp == NULL || scmp == NULL || conp == NULL || conp->connected == 0 ||
       tabp == NULL || tabp->hname == NULL || srch == NULL || ins == NULL )
    return(ERR_SCM_INVALARG);
// check that the 0th entry in both srch and ins is an "id"
  if ( srch->vec == NULL || srch->nused < 1 || srch->vec[0].colname == NULL ||
       strstr(srch->vec[0].colname, "id") == NULL )
    return(ERR_SCM_INVALARG);
  if ( ins->vec == NULL || ins->nused < 1 || ins->vec[0].column == NULL ||
       strstr(ins->vec[0].column, "id") == NULL )
    return(ERR_SCM_INVALARG);
  *idp = (unsigned int)(-1);
  *(unsigned int *)(srch->context) = (unsigned int)(-1);
  sta = searchscm(conp, tabp, srch, NULL, socvaluefunc,
		  SCM_SRCH_DOVALUE_ALWAYS);
  if ( sta == 0 )
    {
      mid = *(unsigned int *)(srch->context);
      if ( mid != (unsigned int)(-1) )
	{
	  *idp = mid;
	  return(0);
	}
    }
  sta = getmaxidscm(scmp, conp, mtab, tabp->hname, &mid);
  if ( sta < 0 )
    return(sta);
  mid++;
  tmp = ins->vec[0].value;
  if ( tmp != NULL )
    {
      free(tmp);
      ins->vec[0].value = NULL;
    }
  ins->vec[0].value = (char *)calloc(16, sizeof(char));
  if ( ins->vec[0].value == NULL )
    return(ERR_SCM_NOMEM);
  (void)sprintf(ins->vec[0].value, "%u", mid);
  sta = insertscm(conp, tabp, ins);
  free((void *)(ins->vec[0].value));
  if ( sta < 0 )
    return(sta);
  sta = setmaxidscm(scmp, conp, mtab, tabp->hname, mid);
  if ( sta < 0 )
    return(sta);
  *idp = mid;
  return(0);
}

/*
  This function deletes entries in a database table that match
  the stated search criteria.
*/

int deletescm(scmcon *conp, scmtab *tabp, scmkva *deld)
{
  char *stmt = NULL;
  int   leen = 128;
  int   sta = 0;
  int   i;

// validate arguments
  if ( conp == NULL || conp->connected == 0 || tabp == NULL ||
       tabp->tabname == NULL || deld == NULL )
    return(ERR_SCM_INVALARG);
  if ( deld->vald == 0 )
    {
      sta = valcols(conp, tabp, deld);
      if ( sta < 0 )
	return(sta);
      deld->vald = 1;
    }
// glean the length of the statement
  leen += strlen(tabp->tabname);
  for(i=0;i<deld->nused;i++)
    {
      leen += strlen(deld->vec[i].column) + 2;
      leen += strlen(deld->vec[i].value) + 9;
    }
// construct the DELETE statement
  conp->mystat.tabname = tabp->hname;
  stmt = (char *)calloc(leen, sizeof(char));
  if ( stmt == NULL )
    return(ERR_SCM_NOMEM);
  (void)sprintf(stmt, "DELETE FROM %s", tabp->tabname);
  if ( deld != NULL )
    {
      (void)strcat(stmt, " WHERE ");
      (void)strcat(stmt, deld->vec[0].column);
      (void)strcat(stmt, "=\"");
      (void)strcat(stmt, deld->vec[0].value);
      (void)strcat(stmt, "\"");
      for(i=1;i<deld->nused;i++)
	{
	  (void)strcat(stmt, " AND ");
	  (void)strcat(stmt, deld->vec[i].column);
	  (void)strcat(stmt, "=\"");
	  (void)strcat(stmt, deld->vec[i].value);
	  (void)strcat(stmt, "\"");
	}
    }
  (void)strcat(stmt, ";");
// execute the DELETE statement
  sta = statementscm(conp, stmt);
  free((void *)stmt);
  return(sta);
}

/*
  Set the flags value on a match corresponding to a search criterion.

  This function returns 0 on success and a negative error code on failure.
*/

int setflagsscm(scmcon *conp, scmtab *tabp, scmkva *where,
		unsigned int flags)
{
  char *stmt;
  int   leen = 128;
  int   sta;
  int   i;

  if ( conp == NULL || conp->connected == 0 || tabp == NULL ||
       tabp->tabname == NULL || where == NULL )
    return(ERR_SCM_INVALARG);
// compute the size of the statement
  leen += strlen(tabp->tabname);
  for(i=0;i<where->nused;i++)
    {
      leen += strlen(where->vec[i].column) + 7;
      leen += strlen(where->vec[i].value) + 3;
    }
  stmt = (char *)calloc(leen, sizeof(char));
  if ( stmt == NULL )
    return(ERR_SCM_NOMEM);
  (void)sprintf(stmt, "UPDATE %s SET flags=%u WHERE ", tabp->tabname, flags);
  (void)strcat(stmt, where->vec[0].column);
  (void)strcat(stmt, "=\"");
  (void)strcat(stmt, where->vec[0].value);
  (void)strcat(stmt, "\"");
  for(i=1;i<where->nused;i++)
    {
      (void)strcat(stmt, " AND ");
      (void)strcat(stmt, where->vec[0].column);
      (void)strcat(stmt, "=\"");
      (void)strcat(stmt, where->vec[0].value);
      (void)strcat(stmt, "\"");
    }
  sta = statementscm(conp, stmt);
  free((void *)stmt);
  return(sta);
}

/*
  Convert a binary array into a hex string.
*/

char *hexify(unsigned int lllen, void *ptr)
{
  unsigned char *inptr;
  char *aptr;
  char *outptr;
  int   lllim;
  int   i;

  lllim = lllen*sizeof(unsigned long long);
  aptr = (char *)calloc(lllim+lllim+24, sizeof(char));
  if ( aptr == NULL )
    return(NULL);
  inptr = (unsigned char *)ptr;
  outptr = aptr;
  *outptr++ = '0';
  *outptr++ = 'x';
  for(i=0;i<lllim;i++)
    {
      (void)sprintf(outptr, "%2.2x", *inptr);
      outptr += 2;
      inptr++;
    }
  *outptr = 0;
  return(aptr);
}

/*
  This very specific function updates the sninuse and snlist entries
  on a CRL using the local_id as the where criterion.
*/

int updateblobscm(scmcon *conp, scmtab *tabp, unsigned long long *snlist,
		  unsigned int sninuse, unsigned int snlen, unsigned int lid)
{
  char *stmt;
  char *hexi;
  int   leen = 128;
  int   sta;

  if ( conp == NULL || conp->connected == 0 || tabp == NULL ||
       tabp->tabname == NULL )
    return(ERR_SCM_INVALARG);
  hexi = hexify(snlen, (void *)snlist);
  if ( hexi == NULL )
    return(ERR_SCM_NOMEM);
// compute the size of the statement
  leen += strlen(hexi);
  stmt = (char *)calloc(leen, sizeof(char));
  if ( stmt == NULL )
    return(ERR_SCM_NOMEM);
  (void)sprintf(stmt, "UPDATE %s SET sninuse=%u, snlist=%s WHERE local_id=%u;",
		tabp->tabname, sninuse, hexi, lid);
  sta = statementscm(conp, stmt);
  free((void *)stmt);
  free((void *)hexi);
  return(sta);
}
