/*
  $Id$
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "scm.h"
#include "scmf.h"

#ifdef NOTDEF
#ifdef WINDOWS
#include <windows.h>
#else  // WINDOWS
#include <memory.h>
#include <time.h>
#endif // WINDOWS

// do an SQL statement operation

static void docatalog(SQLHSTMT h, char *stm, char *what)
{
  SQLINTEGER  istm;
  SQLRETURN   ret;

  istm = strlen(stm);
  ret = SQLExecDirect(h, (SQLCHAR *)stm, istm);
  if ( SQLOK(ret) )
    {
      (void)printf("%s ok\n", what);
      istm = 0;
      ret = SQLRowCount(h, &istm);
      if ( SQLOK(ret) )
	(void)printf("Rows affected = %d\n", (int)istm);
    }
}

// drop the custom table

static void drop(SQLHSTMT h)
{
  docatalog(h,
	    "DROP TABLE IF EXISTS my_odbc_net",
	    "Conditional drop");
}

// create the custom table

static void create(SQLHSTMT h)
{
  docatalog(h,
	    "CREATE TABLE my_odbc_net(id int, name varchar(20), idb bigint)",
	    "Create");
}

// add a variable value pair with a 64-bit timestamp

#ifdef WINDOWS

static void add(SQLHSTMT h, int v1, char *v2)
{
  LARGE_INTEGER large;
  FILETIME ft;
  char tmp[512];

  GetSystemTimeAsFileTime(&ft);
  large.LowPart = ft.dwLowDateTime;
  large.HighPart = ft.dwHighDateTime;
//      (void)sprintf(tmp, "INSERT INTO my_odbc_net (id, name, idb) VALUES (%d, '%s', %d)",
  (void)sprintf(tmp, "INSERT INTO my_odbc_net VALUES (%d, '%s', %I64d)",
                v1, v2, large.QuadPart);
  docatalog(h, tmp, "Add");
}

// windows does not have sleep(sec), it has Sleep(ms)

static void sleep(int s)
{
  Sleep(s*1000);
}

#else  // WINDOWS

static void add(SQLHSTMT h, int v1, char *v2)
{
  unsigned long long large;
  struct timespec tp;
  char tmp[512];

  clock_gettime(CLOCK_REALTIME, &tp);
  large = tp.tv_sec;
  large *= (unsigned long long)1000000000;
  large += tp.tv_nsec;
//      (void)sprintf(tmp, "INSERT INTO my_odbc_net (id, name, idb) VALUES (%d, '%s', %d)",
  (void)sprintf(tmp, "INSERT INTO my_odbc_net VALUES (%d, '%s', %llu)",
                v1, v2, large);
  docatalog(h, tmp, "Add");
}

#endif // WINDOWS

// update a column value to another value

static void update(SQLHSTMT h, int v1, int newv1)
{
  char tmp[512];

  (void)sprintf(tmp, "UPDATE my_odbc_net SET id=%d WHERE id=%d",
                newv1, v1);
  docatalog(h, tmp, "Update");
}

// count the number of rows in the table

static void count(SQLHSTMT h)
{
  SQLRETURN   ret;
  SQLSMALLINT ire;
  SQLSMALLINT nlen;
  SQLSMALLINT dt;
  SQLUINTEGER csz;
  SQLINTEGER  iv;
  SQLSMALLINT ddig;
  SQLSMALLINT nullo;
  unsigned long ival = 0;
  char colo[256];

  docatalog(h, "SELECT COUNT(*) AS TRows FROM my_odbc_net", "Count");
  ret = SQLNumResultCols(h, &ire);
  if ( ! SQLOK(ret) )
    return;
  (void)printf("Number of result columns = %d\n", ire);
  ret = SQLDescribeCol(h, 1, (SQLCHAR *)&colo[0], 256, &nlen, &dt, &csz,
		       &ddig, &nullo);
  if ( ! SQLOK(ret) )
    return;
  (void)printf("Column 1 name %s\n", colo);
  ret = SQLBindCol(h, 1, SQL_C_ULONG, (SQLPOINTER)&ival,
		   sizeof(unsigned long), &iv);
  if ( ! SQLOK(ret) )
    return;
  ret = SQLFetch(h);
  if ( ! SQLOK(ret) )
    return;
  (void)printf("Count = %lu\n", ival);
  SQLCloseCursor(h);
}

// query all rows

static void query(SQLHSTMT h)
{
  SQLINTEGER field1;
  SQLCHAR    field2[256];
  SQLBIGINT  field3;
  SQLINTEGER field1len;
  SQLINTEGER field2len;
  SQLINTEGER field3len;
  SQLRETURN  rc;

  docatalog(h, "SELECT * FROM my_odbc_net", "Query");
  SQLBindCol(h, 1, SQL_C_ULONG, &field1, sizeof(SQLINTEGER), &field1len);
  SQLBindCol(h, 2, SQL_C_CHAR, field2, 256*sizeof(SQLCHAR), &field2len);
  SQLBindCol(h, 3, SQL_C_SBIGINT, &field3, sizeof(SQLBIGINT), &field3len);
  while ( (rc = SQLFetch(h)) != SQL_NO_DATA )
    {
      if ( field1len == SQL_NULL_DATA )
	(void)printf("x");
      else
	(void)printf("%d", (int)field1);
      if ( field2len == SQL_NULL_DATA )
	(void)printf("\tNULL");
      else
	{
	  field2[field2len] = 0;
	  (void)printf("\t%s", field2);
	}
      if ( field3len == SQL_NULL_DATA )
	(void)printf("\tx\n");
      else
#ifdef WINDOWS
	(void)printf("\t%I64d\n", field3);
#else  // WINDOWS
      (void)printf("\t%llu\n", field3);
#endif // WINDOWS
    }
  SQLCloseCursor(h);
}

#endif  // NOTDEF

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
      if ( errmsg != NULL && emlen > strlen(nulldsn) )
	(void)strcpy(errmsg, nulldsn);
      return(NULL);
    }
  conp = (scmcon *)calloc(1, sizeof(scmcon));
  if ( conp == NULL )
    {
      if ( errmsg != NULL && emlen > strlen(oom) )
	(void)strcpy(errmsg, oom);
      return(NULL);
    }
  conp->mystat.errmsg = (char *)calloc(1024, sizeof(char));
  if ( conp->mystat.errmsg == NULL )
    {
      if ( errmsg != NULL && emlen > strlen(oom) )
	(void)strcpy(errmsg, oom);
      free((void *)conp);
      return(NULL);
    }
  conp->mystat.emlen = 1024;
  ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &conp->henv);
  if ( ! SQLOK(ret) )
    {
      disconnectscm(conp);
      if ( errmsg != NULL && emlen > strlen(badhenv) )
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

int insertscm(scmcon *conp, scmtab *tabp, scmkva *arr, int vald)
{
  char *stmt;
  int   sta;
  int   leen = 128;
  int   i;

  if ( conp == NULL || conp->connected == 0 || tabp == NULL ||
       tabp->tabname == NULL )
    return(ERR_SCM_INVALARG);
// handle the trivial cases first
  if ( arr == NULL || arr->nused <= 0 || arr->vec == NULL )
    return(0);
// if the columns listed in arr have not already been validated
// against the set of columns present in the table, then do so
  if ( vald == 0 )
    {
      sta = valcols(conp, tabp, arr);
      if ( sta < 0 )
	return(sta);
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
  (void)strcat(stmt, ") VALUES (\"");
  (void)strcat(stmt, arr->vec[0].value);
  for(i=1;i<arr->nused;i++)
    {
      (void)strcat(stmt, "\", \"");
      (void)strcat(stmt, arr->vec[i].value);
    }
  (void)strcat(stmt, "\");");
  sta = statementscm(conp, stmt);
  free((void *)stmt);
  return(sta);
}
