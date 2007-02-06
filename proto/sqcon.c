/*
  $Id$
*/

#include <stdio.h>
#ifdef WINDOWS
#include <windows.h>
#else
#include <memory.h>
#include <time.h>
#endif

#include "scmf.h"

// decode the last error on a handle

static void heer(void *h, int what, char *errmsg, int emlen)
{
  SQLINTEGER  nep;
  SQLSMALLINT tl;
  char state[24];

  SQLGetDiagRec(what, h, 1, (SQLCHAR *)&state[0], &nep,
                (SQLCHAR *)errmsg, emlen, &tl);
}

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
	(void)printf("Rows affected = %d\n", istm);
    }
  else
    heer(h, what);
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

#else

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

#endif

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
  (void)printf("Count = %d\n", ival);
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
	(void)printf("%d", field1);
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
#else
      (void)printf("\t%llu\n", field3);
#endif
    }
  SQLCloseCursor(h);
}

/*
  Initialize a connection to the named DSN. Return a connection object on
  success and a negative error code on failure.
*/

scmcon *connectscm(char *dsnp, char *errmsg, int emlen)
{
  static char nulldsn[] = "NULL DSN";
  static char badhenv[] = "Cannot allocate HENV handle";
  static char oom[] = "Out of memory!";
  scmcon     *conp;
  SQLRETURN   ret;

  SQLHDBC     hdbc1 = NULL;
  SQLHSTMT    hstmt1 = NULL;
  SQLSMALLINT inret;
  SQLSMALLINT outret;
  char outlen[1024];
  int  connd = 0;

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
	{
	  (void)printf("Success setting v3\n");
	  ret = SQLAllocHandle(SQL_HANDLE_DBC, henv1, &hdbc1);
	  (void)printf("DBC Handle is 0x%x\n", hdbc1);
	  if ( SQLOK(ret) )
	    {
	      (void)printf("Success opening dbc handle\n");
	      inret = strlen(leon);
	      ret = SQLDriverConnect(hdbc1, NULL, (SQLCHAR *)&leon[0], inret,
				     (SQLCHAR *)&outlen[0], 1024, &outret, 0);
	      if ( !SQLOK(ret) )
		heer2(hdbc1, "connect");
	      else
		{
		  (void)printf("Success connecting to data source\n");
//                (void)printf("Completed connection string is %s\n", outlen);
		  sleep(1);
		  ret = SQLAllocHandle(SQL_HANDLE_STMT, hdbc1, &hstmt1);
		  if ( SQLOK(ret) )
		    {
		      (void)printf("Success allocating statement\n");
		      ret = SQLSetStmtAttr(hstmt1, SQL_ATTR_NOSCAN,
					   (SQLPOINTER)SQL_NOSCAN_ON,
					   SQL_IS_UINTEGER);
		      if ( SQLOK(ret) )
			(void)printf("Success turning off param scanning\n");
		      drop(hstmt1);
		      create(hstmt1);
		      add(hstmt1, 10, "fear");
		      add(hstmt1, 20, "greggreg");
		      add(hstmt1, 30, "leonburger");
		      update(hstmt1, 20, 299);
		      add(hstmt1, 300, "garbow");
		      add(hstmt1, 303, "martenizing");
		      count(hstmt1);
		      sleep(1);
		      query(hstmt1);
		    }
		  connd++;
		}
	    }
	}
    }
  sleep(5);
  if ( hstmt1 != NULL )
    {
      SQLFreeHandle(SQL_HANDLE_STMT, hstmt1);
      hstmt1 = NULL;
    }
  if ( connd > 0 )
    {
      SQLDisconnect(hdbc1);
      connd = 0;
    }
  if ( hdbc1 != NULL )
    {
      SQLFreeHandle(SQL_HANDLE_DBC, hdbc1);
      hdbc1 = NULL;
    }
  if ( henv1 != NULL )
    {
      SQLFreeHandle(SQL_HANDLE_ENV, henv1);
      henv1 = NULL;
    }
  return(0);
}
