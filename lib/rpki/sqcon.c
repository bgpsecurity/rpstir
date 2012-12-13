/*
 * $Id$ 
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include <mysql.h>

#include "scm.h"
#include "scmf.h"
#include "diru.h"
#include "err.h"
#include "globals.h"


/*
 * Decode the last error on a handle 
 */

static void heer(
    void *h,
    int what,
    char *errmsg,
    int emlen)
{
    SQLINTEGER nep;
    SQLSMALLINT tl;
    char state[24];

    SQLGetDiagRec(what, h, 1, (SQLCHAR *) & state[0], &nep,
                  (SQLCHAR *) errmsg, emlen, &tl);
}

/*
 * Free a stack of SQLHSTMTs. 
 */

static void freehstack(
    stmtstk * stackp)
{
    stmtstk *nextp;

    while (stackp != NULL)
    {
        if (stackp->hstmt != NULL)
        {
            SQLFreeHandle(SQL_HANDLE_STMT, stackp->hstmt);
            stackp->hstmt = NULL;
        }
        nextp = stackp->next;
        free((void *)stackp);
        stackp = nextp;
    }
}

/*
 * Disconnect from a DSN and free all memory. 
 */

void disconnectscm(
    scmcon * conp)
{
    if (conp == NULL)
        return;
    freehstack(conp->hstmtp);
    /*
     * if ( conp->hstmt != NULL ) { SQLFreeHandle(SQL_HANDLE_STMT,
     * conp->hstmt); conp->hstmt = NULL; } 
     */
    if (conp->connected > 0)
    {
        SQLDisconnect(conp->hdbc);
        conp->connected = 0;
    }
    if (conp->hdbc != NULL)
    {
        SQLFreeHandle(SQL_HANDLE_DBC, conp->hdbc);
        conp->hdbc = NULL;
    }
    if (conp->henv != NULL)
    {
        SQLFreeHandle(SQL_HANDLE_ENV, conp->henv);
        conp->henv = NULL;
    }
    if (conp->mystat.errmsg != NULL)
    {
        free((void *)(conp->mystat.errmsg));
        conp->mystat.errmsg = NULL;
    }
    free((void *)conp);
}

/*
 * ret = SQLAllocHandle(SQL_HANDLE_STMT, conp->hdbc, &conp->hstmt); if ( !
 * SQLOK(ret) ) { if ( errmsg != NULL && emlen > 0 ) heer((void *)conp->hdbc,
 * SQL_HANDLE_DBC, errmsg, emlen); disconnectscm(conp); return(NULL); } ret =
 * SQLSetStmtAttr(conp->hstmt, SQL_ATTR_NOSCAN, (SQLPOINTER)SQL_NOSCAN_ON,
 * SQL_IS_UINTEGER); 
 */

/*
 * Create a new STMT and push it onto the top of the stack of STMTs in the
 * connection. 
 */

SQLRETURN newhstmt(
    scmcon * conp)
{
    SQLRETURN ret;
    stmtstk *stackp;

    if (conp == NULL)
        return (-1);
    stackp = (stmtstk *) calloc(1, sizeof(stmtstk));
    if (stackp == NULL)
        return (-1);
    ret = SQLAllocHandle(SQL_HANDLE_STMT, conp->hdbc, &stackp->hstmt);
    if (!SQLOK(ret))
    {
        free((void *)stackp);
        return (ret);
    }
    ret = SQLSetStmtAttr(stackp->hstmt, SQL_ATTR_NOSCAN,
                         (SQLPOINTER) SQL_NOSCAN_ON, SQL_IS_UINTEGER);
    if (!SQLOK(ret))
    {
        SQLFreeHandle(SQL_HANDLE_STMT, stackp->hstmt);
        free((void *)stackp);
        return (ret);
    }
    stackp->next = conp->hstmtp;
    conp->hstmtp = stackp;
    return (0);
}

/*
 * Pop the top element off the hstmt stack of a connection, free the hstmt and 
 * the associated memory. 
 */

void pophstmt(
    scmcon * conp)
{
    stmtstk *stackp;

    if (conp == NULL)
        return;
    stackp = conp->hstmtp;
    if (stackp == NULL)
        return;
    conp->hstmtp = stackp->next;
    if (stackp->hstmt != NULL)
        SQLFreeHandle(SQL_HANDLE_STMT, stackp->hstmt);
    free((void *)stackp);
}

/*
 * Initialize a connection to the named DSN. Return a connection object on
 * success and a negative error code on failure. 
 */

scmcon *connectscm(
    char *dsnp,
    char *errmsg,
    int emlen)
{
    SQLSMALLINT inret;
    SQLSMALLINT outret;
    static char nulldsn[] = "NULL DSN";
    static char badhenv[] = "Cannot allocate HENV handle";
    static char oom[] = "Out of memory!";
    scmcon *conp;
    SQLRETURN ret;
    char outlen[1024];
    int leen;

    if (errmsg != NULL && emlen > 0)
        memset(errmsg, 0, emlen);
    if (dsnp == NULL || dsnp[0] == 0)
    {
        leen = strlen(nulldsn);
        if (errmsg != NULL && emlen > leen)
            (void)strncpy(errmsg, nulldsn, leen);
        return (NULL);
    }
    conp = (scmcon *) calloc(1, sizeof(scmcon));
    if (conp == NULL)
    {
        leen = strlen(oom);
        if (errmsg != NULL && emlen > leen)
            (void)strncpy(errmsg, oom, leen);
        return (NULL);
    }
    conp->mystat.errmsg = (char *)calloc(1024, sizeof(char));
    if (conp->mystat.errmsg == NULL)
    {
        leen = strlen(oom);
        if (errmsg != NULL && emlen > leen)
            (void)strncpy(errmsg, oom, leen);
        free((void *)conp);
        return (NULL);
    }
    conp->mystat.emlen = 1024;
    ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &conp->henv);
    if (!SQLOK(ret))
    {
        disconnectscm(conp);
        leen = strlen(badhenv);
        if (errmsg != NULL && emlen > leen)
            (void)strncpy(errmsg, badhenv, leen);
        return (NULL);
    }
    ret = SQLSetEnvAttr(conp->henv, SQL_ATTR_ODBC_VERSION,
                        (SQLPOINTER) SQL_OV_ODBC3, sizeof(int));
    if (!SQLOK(ret))
    {
        if (errmsg != NULL && emlen > 0)
            heer((void *)conp->henv, SQL_HANDLE_ENV, errmsg, emlen);
        disconnectscm(conp);
        return (NULL);
    }
    ret = SQLAllocHandle(SQL_HANDLE_DBC, conp->henv, &conp->hdbc);
    if (!SQLOK(ret))
    {
        if (errmsg != NULL && emlen > 0)
            heer((void *)conp->henv, SQL_HANDLE_ENV, errmsg, emlen);
        disconnectscm(conp);
        return (NULL);
    }
    inret = strlen(dsnp) + 1;
    ret = SQLDriverConnect(conp->hdbc, NULL, (SQLCHAR *) dsnp, inret,
                           (SQLCHAR *) & outlen[0], 1024, &outret, 0);
    if (!SQLOK(ret))
    {
        if (errmsg != NULL && emlen > 0)
            heer((void *)conp->hdbc, SQL_HANDLE_DBC, errmsg, emlen);
        // disconnectscm(conp); # if not connected, cannot disconnect
        return (NULL);
    }
    conp->connected++;
    ret = newhstmt(conp);
    if (!SQLOK(ret))
    {
        if (errmsg != NULL && emlen > 0 && conp->hstmtp != NULL &&
            conp->hstmtp->hstmt != NULL)
            heer((void *)(conp->hstmtp->hstmt), SQL_HANDLE_STMT, errmsg,
                 emlen);
        disconnectscm(conp);
        return (NULL);
    }
    /*
     * ret = SQLAllocHandle(SQL_HANDLE_STMT, conp->hdbc, &conp->hstmt); if ( ! 
     * SQLOK(ret) ) { if ( errmsg != NULL && emlen > 0 ) heer((void
     * *)conp->hdbc, SQL_HANDLE_DBC, errmsg, emlen); disconnectscm(conp);
     * return(NULL); } ret = SQLSetStmtAttr(conp->hstmt, SQL_ATTR_NOSCAN,
     * (SQLPOINTER)SQL_NOSCAN_ON, SQL_IS_UINTEGER); 
     */
    return (conp);
}

/*
 * Get the error message from a connection. 
 */

char *geterrorscm(
    scmcon * conp)
{
    if (conp == NULL || conp->mystat.errmsg == NULL)
        return (NULL);
    return (conp->mystat.errmsg);
}

/*
 * Get the name of the table that had an error. 
 */

char *gettablescm(
    scmcon * conp)
{
    if (conp == NULL)
        return (NULL);
    return (conp->mystat.tabname);
}


/*
 * Get the number of rows returned by a statement. 
 */

int getrowsscm(
    scmcon * conp)
{
    int r;

    if (conp == NULL)
        return (ERR_SCM_INVALARG);
    r = conp->mystat.rows;
    return (r);
}

/*
 * Execute an SQL statement.
 * 
 * Before calling statementscm: You must call newhstmt(conp) and verify its
 * return value.
 * 
 * After calling statementscm and using its statement handle: You must call
 * pophstmt(conp). 
 */

int statementscm(
    scmcon * conp,
    char *stm)
{
    SQLINTEGER istm;
    SQLRETURN ret;

    if (conp == NULL || conp->connected == 0 || stm == NULL || stm[0] == 0)
        return (ERR_SCM_INVALARG);
    memset(conp->mystat.errmsg, 0, conp->mystat.emlen);
    istm = strlen(stm);
    ret = SQLExecDirect(conp->hstmtp->hstmt, (SQLCHAR *) stm, istm);
    if (!SQLOK(ret))
    {
        heer((void *)(conp->hstmtp->hstmt), SQL_HANDLE_STMT,
             conp->mystat.errmsg, conp->mystat.emlen);
        return (ERR_SCM_SQL);
    }
    istm = 0;
    ret = SQLRowCount(conp->hstmtp->hstmt, &istm);
    if (!SQLOK(ret))
    {
        heer((void *)(conp->hstmtp->hstmt), SQL_HANDLE_STMT,
             conp->mystat.errmsg, conp->mystat.emlen);
        return (ERR_SCM_SQL);
    }
    return (0);
}

/*
 * Execute a SQL statement, ignoring any returned rows. 
 */

int statementscm_no_data(
    scmcon * conp,
    char *stm)
{
    SQLRETURN ret;

    ret = newhstmt(conp);
    if (!SQLOK(ret))
        return ret;

    ret = statementscm(conp, stm);

    pophstmt(conp);

    return ret;
}


/*
 * Create a database and grant the mysql default user the standard set of
 * privileges for that database. 
 */

int createdbscm(
    scmcon * conp,
    char *dbname,
    char *dbuser)
{
    char *mk;
    int sta;
    int leen;

    if (dbname == NULL || dbname[0] == 0 || conp == NULL ||
        conp->connected == 0 || dbuser == NULL || dbuser[0] == 0)
        return (ERR_SCM_INVALARG);
    leen = strlen(dbname) + strlen(dbuser) + 130;
    mk = (char *)calloc(leen, sizeof(char));
    if (mk == NULL)
        return (ERR_SCM_NOMEM);
    (void)snprintf(mk, leen, "CREATE DATABASE %s;", dbname);
    sta = statementscm_no_data(conp, mk);
    if (sta < 0)
    {
        free((void *)mk);
        return (sta);
    }
    (void)snprintf(mk, leen,
                   "GRANT DELETE, INSERT, LOCK TABLES, SELECT, UPDATE ON %s.* TO '%s'@'localhost';",
                   dbname, dbuser);
    sta = statementscm_no_data(conp, mk);
    free((void *)mk);
    return (sta);
}

/*
 * Delete a database. 
 */

int deletedbscm(
    scmcon * conp,
    char *dbname)
{
    char *mk;
    int sta;
    int leen;

    if (dbname == NULL || dbname[0] == 0 || conp == NULL ||
        conp->connected == 0)
        return (ERR_SCM_INVALARG);
    leen = strlen(dbname) + 30;
    mk = (char *)calloc(leen, sizeof(char));
    if (mk == NULL)
        return (ERR_SCM_NOMEM);
    (void)snprintf(mk, leen, "DROP DATABASE IF EXISTS %s;", dbname);
    sta = statementscm_no_data(conp, mk);
    free((void *)mk);
    return (sta);
}

/*
 * Create a single table. 
 */

static int createonetablescm(
    scmcon * conp,
    scmtab * tabp)
{
    char *mk;
    int sta;
    int leen;

    if (tabp->tstr == NULL || tabp->tstr[0] == 0)
        return (0);             /* no op */
    conp->mystat.tabname = tabp->hname;
    leen = strlen(tabp->tabname) + strlen(tabp->tstr) + 100;
    mk = (char *)calloc(leen, sizeof(char));
    if (mk == NULL)
        return (ERR_SCM_NOMEM);
    (void)snprintf(mk, leen, "CREATE TABLE %s ( %s ) ENGINE=InnoDB;",
                   tabp->tabname, tabp->tstr);
    sta = statementscm_no_data(conp, mk);
    free((void *)mk);
    return (sta);
}

/*
 * Create all the tables listed in scmp. This assumes that the database has
 * already been created through a call to createdbscm(). 
 */

int createalltablesscm(
    scmcon * conp,
    scm * scmp)
{
    char *mk;
    int sta = 0;
    int leen;
    int i;

    if (conp == NULL || conp->connected == 0 || scmp == NULL)
        return (ERR_SCM_INVALARG);
    if (scmp->ntables > 0 && scmp->tables == NULL)
        return (ERR_SCM_INVALARG);
    leen = strlen(scmp->db) + 30;
    mk = (char *)calloc(leen, sizeof(char));
    if (mk == NULL)
        return (ERR_SCM_NOMEM);
    (void)snprintf(mk, leen, "USE %s;", scmp->db);
    sta = statementscm_no_data(conp, mk);
    if (sta < 0)
        return (sta);
    for (i = 0; i < scmp->ntables; i++)
    {
        sta = createonetablescm(conp, &scmp->tables[i]);
        if (sta < 0)
            break;
    }
    return (sta);
}

/*
 * Return the index of the named column in the given schema table, or a
 * negative error code on failure. 
 */

static int findcol(
    scmtab * tabp,
    char *coln)
{
    char *ptr;
    int i;

    if (tabp == NULL || coln == NULL || coln[0] == 0)
        return (-1);
    if (tabp->cols == NULL || tabp->ncols <= 0)
        return (-2);
    for (i = 0; i < tabp->ncols; i++)
    {
        ptr = tabp->cols[i];
        if (ptr != NULL && ptr[0] != 0 && strcasecmp(ptr, coln) == 0)
            return (i);
    }
    return (-3);
}

/*
 * Validate that each of the columns mentioned actually occurs in the
 * indicated table. Return 0 on success and a negative error code on failure. 
 */

static int valcols(
    scmcon * conp,
    scmtab * tabp,
    scmkva * arr)
{
    char *ptr;
    int i;

    if (conp == NULL || tabp == NULL || arr == NULL || arr->vec == NULL)
        return (ERR_SCM_INVALARG);
    for (i = 0; i < arr->nused; i++)
    {
        ptr = arr->vec[i].column;
        if (ptr == NULL || ptr[0] == 0)
            return (ERR_SCM_NULLCOL);
        if (findcol(tabp, ptr) < 0)
        {
            if (conp->mystat.errmsg != NULL)
                (void)snprintf(conp->mystat.errmsg, conp->mystat.emlen,
                               "Invalid column %s", ptr);
            return (ERR_SCM_INVALCOL);
        }
    }
    return (0);
}


/**
 * Quote the input as needed for use in a SQL statement.
 *
 * Note the special convention that if the value (as a string) begins with 
 * ^x it is NOT quoted. The ^x is turned into 0x and then inserted. This
 * is so that we can insert binary strings in their hex representation
 * without having to pass in column information. Thus if we said
 * ^x00656667 -> 0x00656667 as the value it would get inserted as NULefg
 * but if we said "0x00656667" it would get inserted as the string
 * 0x00656667. 
 *
 * @return 0 on success, error code on error
 */
static int quote_value(
    const char * input,
    char ** output)
{
    size_t i;
    size_t len;
    unsigned long escaped_length;

    if (strncmp(input, "^x", 2) == 0)
    {
        for (i = 2; input[i] != '\0'; ++i)
        {
            if (!isxdigit((int)(unsigned char)input[i]))
            {
                return ERR_SCM_INVALARG;
            }
        }

        *output = strdup(input);
        if (*output == NULL)
        {
            return ERR_SCM_NOMEM;
        }

        (*output)[0] = '0';

        return 0;
    }
    else
    {
        len = strlen(input);

        *output = malloc(1 /* '"' */ +
                         len * 2 /* escaped string*/ +
                         1 /* '"' */ +
                         1 /* '\0' */);
        if (*output == NULL)
        {
            return ERR_SCM_NOMEM;
        }

        (*output)[0] = '"';

        escaped_length = mysql_escape_string(&(*output)[1], input, len);

        (*output)[1 + escaped_length] = '"';
        (*output)[1 + escaped_length + 1] = '\0';

        return 0;
    }
}


/*
 * Insert an entry into a database table. 
 */

int insertscm(
    scmcon * conp,
    scmtab * tabp,
    scmkva * arr)
{
    char *stmt;
    char *quoted = NULL;
    int sta;
    int leen = 128;
    int wsta = (-1);
    int i;

    if (conp == NULL || conp->connected == 0 || tabp == NULL ||
        tabp->tabname == NULL)
        return (ERR_SCM_INVALARG);
    conp->mystat.tabname = tabp->hname;
    // handle the trivial cases first
    if (arr == NULL || arr->nused <= 0 || arr->vec == NULL)
        return (0);
    // if the columns listed in arr have not already been validated
    // against the set of columns present in the table, then do so
    if (arr->vald == 0)
    {
        sta = valcols(conp, tabp, arr);
        if (sta < 0)
            return (sta);
        arr->vald = 1;
    }
    // glean the length of the statement
    leen += strlen(tabp->tabname);
    for (i = 0; i < arr->nused; i++)
    {
        leen += strlen(arr->vec[i].column) + 2;
        leen += 2 * strlen(arr->vec[i].value) + 4;
    }
    // construct the statement
    stmt = (char *)calloc(leen, sizeof(char));
    if (stmt == NULL)
        return (ERR_SCM_NOMEM);
    (void)snprintf(stmt, leen, "INSERT INTO %s (%s", tabp->tabname,
                   arr->vec[0].column);
    for (i = 1; i < arr->nused; i++)
    {
        wsta = strwillfit(stmt, leen, wsta, ", ");
        if (wsta >= 0)
            wsta = strwillfit(stmt, leen, wsta, arr->vec[i].column);
        if (wsta < 0)
        {
            free((void *)stmt);
            return (wsta);
        }
    }
    for (i = 0; i < arr->nused; ++i)
    {
        if (i == 0)
            wsta = strwillfit(stmt, leen, wsta, ") VALUES (");
        else
            wsta = strwillfit(stmt, leen, wsta, ", ");
        if (wsta < 0)
        {
            free((void *)stmt);
            return (wsta);
        }

        sta = quote_value(arr->vec[i].value, &quoted);
        if (sta < 0)
        {
            free(stmt);
            return (sta);
        }

        wsta = strwillfit(stmt, leen, wsta, quoted);

        free(quoted);
        quoted = NULL;

        if (wsta < 0)
        {
            free(stmt);
            return (wsta);
        }
    }
    wsta = strwillfit(stmt, leen, wsta, ");");
    if (wsta < 0)
    {
        free((void *)stmt);
        return (wsta);
    }
    sta = statementscm_no_data(conp, stmt);
    free((void *)stmt);
    return (sta);
}

int getuintscm(
    scmcon * conp,
    unsigned int *ival)
{
    SQLUINTEGER f1;
    SQLINTEGER f1len;
    SQLRETURN rc;
    int fnd = 0;

    if (conp == NULL || conp->connected == 0 || ival == NULL)
        return (ERR_SCM_INVALARG);
    SQLBindCol(conp->hstmtp->hstmt, 1, SQL_C_ULONG, &f1, sizeof(f1), &f1len);
    while (1)
    {
        rc = SQLFetch(conp->hstmtp->hstmt);
        if (rc == SQL_NO_DATA)
            break;
        if (!SQLOK(rc))
            continue;
        if (f1len == SQL_NULL_DATA)
            break;
        fnd++;
        *ival = (unsigned int)f1;
    }
    SQLCloseCursor(conp->hstmtp->hstmt);
    if (fnd == 0)
        return (ERR_SCM_NODATA);
    else
        return (0);
}

/*
 * Get the maximum of the specified id field of the given table.  If table is
 * empty, then sets *ival to 0.  
 */

int getmaxidscm(
    scm * scmp,
    scmcon * conp,
    char *field,
    scmtab * mtab,
    unsigned int *ival)
{
    char stmt[160];
    int sta;

    if (scmp == NULL || conp == NULL || conp->connected == 0 || ival == NULL)
        return (ERR_SCM_INVALARG);
    sta = newhstmt(conp);
    if (!SQLOK(sta))
        return sta;
    (void)snprintf(stmt, sizeof(stmt),
                   "SELECT MAX(%s) FROM %s;", field, mtab->tabname);
    sta = statementscm(conp, stmt);
    if (sta < 0)
        return (sta);
    *ival = 0;
    sta = getuintscm(conp, ival);
    pophstmt(conp);
    if (sta < 0)
        *ival = 0;              /* No rows (or NULL), set max to arbitrary
                                 * value of 0. */
    return 0;
}

/*
 * Validate a search array struct 
 */

static int validsrchscm(
    scmcon * conp,
    scmtab * tabp,
    scmsrcha * srch)
{
    scmsrch *vecp;
    int sta;
    int i;

    if (srch == NULL || srch->vec == NULL || srch->nused <= 0)
        return (ERR_SCM_INVALARG);
    for (i = 0; i < srch->nused; i++)
    {
        vecp = (&srch->vec[i]);
        if (vecp->colname == NULL || vecp->colname[0] == 0)
            return (ERR_SCM_NULLCOL);
        if (vecp->valptr == NULL)
            return (ERR_SCM_NULLVALP);
        if (vecp->valsize == 0)
            return (ERR_SCM_INVALSZ);
    }
    if (srch->where != NULL && srch->where->vald == 0)
    {
        sta = valcols(conp, tabp, srch->where);
        if (sta < 0)
            return (sta);
        srch->where->vald = 1;
    }
    return (0);
}

/*
 * This function searches in a database table for entries that match the
 * stated search criteria.
 * 
 * Note that searchscm can be call recursively, so that there can be more than 
 * one cursor open at a time. For this reason, searchscm() must create its own 
 * STMT and then destroy it when it is done. 
 */

int searchscm(
    scmcon * conp,
    scmtab * tabp,
    scmsrcha * srch,
    sqlcountfunc cnter,
    sqlvaluefunc valer,
    int what,
    char *orderp)
{
    SQLINTEGER nrows = 0;
    SQLRETURN rc;
    scmsrch *vecp;
    char *stmt = NULL;
    char *quoted = NULL;
    int docall;
    int leen = 100;
    int sta = 0;
    int nfnd = 0;
    int bset = 0;
    int ridx = 0;
    int nok = 0;
    int didw = 0;
    int fnd;
    int i;

    // validate arguments
    if (conp == NULL || conp->connected == 0 || tabp == NULL ||
        tabp->tabname == NULL)
        return (ERR_SCM_INVALARG);
    if (srch->vald == 0)
    {
        sta = validsrchscm(conp, tabp, srch);
        if (sta < 0)
            return (sta);
        srch->vald = 1;
    }
    if ((what & SCM_SRCH_DOVALUE))
    {
        if ((what & SCM_SRCH_DOVALUE_ANN))
            bset++;
        if ((what & SCM_SRCH_DOVALUE_SNN))
            bset++;
        if ((what & SCM_SRCH_DOVALUE_ALWAYS))
            bset++;
        if (bset > 1)
            return (ERR_SCM_INVALARG);
    }
    // construct the SELECT statement
    conp->mystat.tabname = tabp->hname;
    leen += strlen(tabp->tabname);
    for (i = 0; i < srch->nused; i++)
        leen += strlen(srch->vec[i].colname) + 2;
    if (srch->where != NULL)
    {
        for (i = 0; i < srch->where->nused; i++)
        {
            leen += strlen(srch->where->vec[i].column) + 9;
            leen += 2 * strlen(srch->where->vec[i].value);
        }
    }
    if (srch->wherestr != NULL)
        leen += strlen(srch->wherestr) + 24;
    if ((what & SCM_SRCH_DO_JOIN))
        leen += strlen(tabp->tabname) + 48;
    if (orderp)
        leen += strlen(orderp) + 16;
    stmt = (char *)calloc(leen, sizeof(char));
    if (stmt == NULL)
        return (ERR_SCM_NOMEM);
    (void)sprintf(stmt, "SELECT %s", srch->vec[0].colname);
    for (i = 1; i < srch->nused; i++)
    {
        (void)strcat(stmt, ", ");
        (void)strcat(stmt, srch->vec[i].colname);
    }
    (void)strcat(stmt, " FROM ");
    (void)strcat(stmt, tabp->tabname);
    // put in the join if requested
    if ((what & SCM_SRCH_DO_JOIN))
    {
        (void)strcat(stmt, " LEFT JOIN rpki_dir on ");
        (void)strcat(stmt, tabp->tabname);
        (void)strcat(stmt, ".dir_id = rpki_dir.dir_id");
    }
    if ((what & SCM_SRCH_DO_JOIN_SELF))
    {
        (void)strcat(stmt, " t1 LEFT JOIN ");
        (void)strcat(stmt, tabp->tabname);
        (void)strcat(stmt, " t2 on ");
        *strchr(srch->wherestr, '\n') = 0;
        (void)strcat(stmt, srch->wherestr);
        (void)strcat(stmt, " where ");
        (void)strcat(stmt, srch->wherestr + strlen(srch->wherestr) + 1);
        srch->wherestr[strlen(srch->wherestr)] = '\n';
    }
    if ((what & SCM_SRCH_DO_JOIN_CRL))
    {
        strcat(stmt, " LEFT JOIN rpki_crl on rpki_cert.aki = rpki_crl.aki");
    }
    if (srch->where != NULL)
    {
        didw++;
        (void)strcat(stmt, " WHERE ");
        (void)strcat(stmt, srch->where->vec[0].column);
        (void)strcat(stmt, "=");
        sta = quote_value(srch->where->vec[0].value, &quoted);
        if (sta < 0)
        {
            free(stmt);
            return sta;
        }
        (void)strcat(stmt, quoted);
        free(quoted);
        quoted = NULL;
        for (i = 1; i < srch->where->nused; i++)
        {
            (void)strcat(stmt, " AND ");
            (void)strcat(stmt, srch->where->vec[i].column);
            (void)strcat(stmt, "=");
            sta = quote_value(srch->where->vec[i].value, &quoted);
            if (sta < 0)
            {
                free(stmt);
                return sta;
            }
            (void)strcat(stmt, quoted);
            free(quoted);
            quoted = NULL;
        }
    }
    if ((srch->wherestr != NULL) && !(what & SCM_SRCH_DO_JOIN_SELF))
    {
        if (didw == 0)
            (void)strcat(stmt, " WHERE ");
        else
            (void)strcat(stmt, " AND ");
        (void)strcat(stmt, srch->wherestr);
    }
    if (orderp)
        sprintf(&stmt[strlen(stmt)], " order by %s ", orderp);

    (void)strcat(stmt, ";");
    // execute the select statement
    rc = newhstmt(conp);
    if (!SQLOK(rc))
    {
        free((void *)stmt);
        return (ERR_SCM_SQL);
    }
    sta = statementscm(conp, stmt);
    free((void *)stmt);
    if (sta < 0)
    {
        SQLCloseCursor(conp->hstmtp->hstmt);
        pophstmt(conp);
        return (sta);
    }
    // count rows and call counter function if requested
    if ((what & SCM_SRCH_DOCOUNT) && cnter != NULL)
    {
        rc = SQLRowCount(conp->hstmtp->hstmt, &nrows);
        if (!SQLOK(rc) && (what & SCM_SRCH_BREAK_CERR))
        {
            heer((void *)(conp->hstmtp->hstmt), SQL_HANDLE_STMT,
                 conp->mystat.errmsg, conp->mystat.emlen);
            SQLCloseCursor(conp->hstmtp->hstmt);
            pophstmt(conp);
            return (ERR_SCM_SQL);
        }
        sta = (*cnter) (conp, srch, (int)nrows);
        if (sta < 0 && (what & SCM_SRCH_BREAK_CERR))
        {
            SQLCloseCursor(conp->hstmtp->hstmt);
            pophstmt(conp);
            return (sta);
        }
    }
    // loop over the results calling the value callback if requested
    if ((what & SCM_SRCH_DOVALUE) && valer != NULL)
    {
        // do the column binding
        for (i = 0; i < srch->nused; i++)
        {
            vecp = (&srch->vec[i]);
            SQLBindCol(conp->hstmtp->hstmt,
                       vecp->colno <= 0 ? i + 1 : vecp->colno, vecp->sqltype,
                       vecp->valptr, vecp->valsize,
                       (SQLINTEGER *) & vecp->avalsize);
        }
        while (1)
        {
            ridx++;
            rc = SQLFetch(conp->hstmtp->hstmt);
            if (rc == SQL_NO_DATA)
                break;
            if (!SQLOK(rc))
            {
                nok++;
                if (nok >= 2)
                    break;
                else
                    continue;
            }
            // count how many columns actually contain data
            fnd = 0;
            for (i = 0; i < srch->nused; i++)
            {
                if (srch->vec[i].avalsize != SQL_NO_DATA)
                    fnd++;
            }
            if (fnd == 0)
                continue;
            nfnd++;
            // determine if the function should be called and call it if so
            // we have already validated that only one of these bits is set
            docall = 0;
            if ((what & SCM_SRCH_DOVALUE_ALWAYS))
                docall++;
            if ((what & SCM_SRCH_DOVALUE_SNN) && (fnd > 0))
                docall++;
            if ((what & SCM_SRCH_DOVALUE_ANN) && (fnd == srch->nused))
                docall++;
            if (docall > 0)
            {
                sta = (valer) (conp, srch, ridx);
                if ((sta < 0) && (what & SCM_SRCH_BREAK_VERR))
                    break;
            }
        }
    }
    SQLCloseCursor(conp->hstmtp->hstmt);
    pophstmt(conp);
    if (sta < 0)
        return (sta);
    if (nfnd == 0)
        return (ERR_SCM_NODATA);
    else
        return (0);
}

/*
 * Free all the memory in a search array 
 */

void freesrchscm(
    scmsrcha * srch)
{
    scmsrch *vecp;
    int i;

    if (srch != NULL)
    {
        if (srch->sname != NULL)
        {
            free((void *)(srch->sname));
            srch->sname = NULL;
        }
        if (srch->context != NULL)
        {
            free(srch->context);
            srch->context = NULL;
        }
        if (srch->wherestr != NULL)
        {
            free(srch->wherestr);
            srch->wherestr = NULL;
        }
        if (srch->vec != NULL)
        {
            for (i = 0; i < srch->nused; i++)
            {
                vecp = &srch->vec[i];
                if (vecp->colname != NULL)
                {
                    free((void *)(vecp->colname));
                    vecp->colname = NULL;
                }
                if (vecp->valptr != NULL)
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
 * add clause for testing the value of a flag to a where string 
 */
void addFlagTest(
    char *whereStr,
    int flagVal,
    int isSet,
    int needAnd)
{
    /*
     * Obfuscated note: the search where string is a spec that tells how to
     * test for the value of a flag being set or clear in a total-flags value
     * using the c mod operator '%'.  A simpler to follow way would be to
     * test using bitwise and and then != 0 or == 0 test, but this is
     * (presumably) not allowed.  The 'mod' test is best understood by example 
     * - so to test for flag 0x04 being set, take the value of total-flags mod 
     * (0x04 * 2) and see if it is >= 0x04 (in which case bit 0x04 is set),
     * or < 0x04 (in which case bit 0x04 is not set). 
     */
    int len = strlen(whereStr);
    snprintf(&whereStr[len], WHERESTR_SIZE - len, "%s ((flags%%%d)%s%d)", needAnd ? " and" : "", 2 * flagVal    /* 2x 
                                                                                                                 * since 
                                                                                                                 * we 
                                                                                                                 * are 
                                                                                                                 * doing 
                                                                                                                 * flag 
                                                                                                                 * mod 
                                                                                                                 * this 
                                                                                                                 * value 
                                                                                                                 */ ,
             isSet ? ">=" : "<", flagVal);
}

/*
 * Create a new empty srch array 
 */

scmsrcha *newsrchscm(
    char *name,
    int leen,
    int cleen,
    int includeWhereStr)
{
    scmsrcha *newp;

    if (leen <= 0)
        return (NULL);
    newp = (scmsrcha *) calloc(1, sizeof(scmsrcha));
    if (newp == NULL)
        return (NULL);
    newp->sname = NULL;
    if (name != NULL && name[0] != 0)
    {
        newp->sname = strdup(name);
        if (newp->sname == NULL)
        {
            freesrchscm(newp);
            return (NULL);
        }
    }
    newp->vec = (scmsrch *) calloc(leen, sizeof(scmsrch));
    if (newp->vec == NULL)
    {
        freesrchscm(newp);
        return (NULL);
    }
    if (cleen <= 0)
        cleen = sizeof(unsigned int);
    newp->context = (void *)calloc(cleen, sizeof(char));
    if (newp->context == NULL)
    {
        freesrchscm(newp);
        return (NULL);
    }
    newp->ntot = leen;
    newp->nused = 0;
    newp->vald = 0;
    newp->wherestr = NULL;
    newp->where = NULL;
    if (includeWhereStr)
    {
        newp->wherestr = (char *)calloc(1, WHERESTR_SIZE);
    }
    return (newp);
}

/*
 * Add a new column to a search array. Note that this function does not grow
 * the size of the column array, so enough space must have already been
 * allocated when the array was created. 
 */

int addcolsrchscm(
    scmsrcha * srch,
    char *colname,
    int sqltype,
    unsigned valsize)
{
    scmsrch *vecp;
    char *cdup;
    void *v;

    if (srch == NULL || srch->vec == NULL || srch->ntot <= 0 ||
        colname == NULL || colname[0] == 0 || valsize == 0)
        return (ERR_SCM_INVALARG);
    if (srch->nused >= srch->ntot)
        return (ERR_SCM_INVALSZ);
    cdup = strdup(colname);
    if (cdup == NULL)
        return (ERR_SCM_NOMEM);
    v = (void *)calloc(1, valsize);
    if (v == NULL)
        return (ERR_SCM_NOMEM);
    vecp = &srch->vec[srch->nused];
    vecp->colno = srch->nused + 1;
    vecp->sqltype = sqltype;
    vecp->colname = cdup;
    vecp->valptr = v;
    vecp->valsize = valsize;
    srch->nused++;
    return (0);
}

/*
 * This is the value function callback for the next function. 
 */

static int socvaluefunc(
    scmcon * conp,
    scmsrcha * s,
    int idx)
{
    UNREFERENCED_PARAMETER(conp);
    UNREFERENCED_PARAMETER(idx);
    if (s->vec[0].sqltype == SQL_C_ULONG &&
        (unsigned)(s->vec[0].avalsize) >= sizeof(unsigned int) &&
        s->context != NULL)
    {
        memcpy(s->context, s->vec[0].valptr, sizeof(unsigned int));
        return (0);
    }
    return (-1);
}

/*
 * This function performs a find-or-create operation for a specific id. It
 * first searches in table "tab" with search criteria "srch". If the entry is
 * found it returns the value of the id. If it isn't found then the max_id is
 * looked up in the metadata table and incremented, a new entry is created in
 * "tab" using the creation criteria "ins", and the max id in the metadata
 * table is updated and returned.
 * 
 * Since this is somewhat convoluted and contains several steps, consider an
 * example.  Suppose I wish to find or create two directories in the directory 
 * table.  These directories are /path/to/somewhere and /path/to/elsewhere.  I 
 * want to get the directory ids for these directories in either case, e.g.
 * whether they are already there or have to be created. If a new directory is 
 * created I also want the maximum directory id in the metadata table to be
 * updated.
 * 
 * Consider the following putative sequence.  I construct a search for
 * "/path/to/somewhere" in the directory table. The first element of the
 * search is the id. The search succeeds, and the id is returned. The metadata 
 * table is unchanged. Now I construct a second search for
 * "/path/to/elsewhere". That search fails. So I fetch the maximum directory
 * id from the metadata table and increment it. I then create an entry in the
 * directory table with elements "/path/to/elsewhere" and that (incremented)
 * id. I update the metadata table's value for the max directory id to the
 * new, incremented id, and, finally, I return that new, incremented id.
 * 
 * Certs, CRLs, ROAs and directories all have ids and their tables all have
 * max ids in the metadata table and so all of them have to be managed using
 * this (sadly prolix) function. 
 */

int searchorcreatescm(
    scm * scmp,
    scmcon * conp,
    scmtab * tabp,
    scmsrcha * srch,
    scmkva * ins,
    unsigned int *idp)
{
    unsigned int mid = 0;
    char *tmp;
    int sta;

    if (idp == NULL || scmp == NULL || conp == NULL || conp->connected == 0 ||
        tabp == NULL || tabp->hname == NULL || srch == NULL || ins == NULL)
        return (ERR_SCM_INVALARG);
    // check that the 0th entry in both srch and ins is an "id"
    if (srch->vec == NULL || srch->nused < 1 || srch->vec[0].colname == NULL ||
        strstr(srch->vec[0].colname, "id") == NULL)
        return (ERR_SCM_INVALARG);
    if (ins->vec == NULL || ins->nused < 1 || ins->vec[0].column == NULL ||
        strstr(ins->vec[0].column, "id") == NULL)
        return (ERR_SCM_INVALARG);
    *idp = (unsigned int)(-1);
    *(unsigned int *)(srch->context) = (unsigned int)(-1);
    sta = searchscm(conp, tabp, srch, NULL, socvaluefunc,
                    SCM_SRCH_DOVALUE_ALWAYS, NULL);
    if (sta == 0)
    {
        mid = *(unsigned int *)(srch->context);
        if (mid != (unsigned int)(-1))
        {
            *idp = mid;
            return (0);
        }
    }
    sta = getmaxidscm(scmp, conp, "dir_id", tabp, &mid);
    if (sta < 0)
        return (sta);
    mid++;
    tmp = ins->vec[0].value;
    if (tmp != NULL)
    {
        free(tmp);
        ins->vec[0].value = NULL;
    }
    ins->vec[0].value = (char *)calloc(16, sizeof(char));
    if (ins->vec[0].value == NULL)
        return (ERR_SCM_NOMEM);
    (void)snprintf(ins->vec[0].value, 16, "%u", mid);
    sta = insertscm(conp, tabp, ins);
    free((void *)(ins->vec[0].value));
    if (sta < 0)
        return (sta);
    *idp = mid;
    return (0);
}

/*
 * This function deletes entries in a database table that match the stated
 * search criteria. 
 */

int deletescm(
    scmcon * conp,
    scmtab * tabp,
    scmkva * deld)
{
    char *stmt = NULL;
    int leen = 128;
    int sta = 0;
    int wsta = (-1);
    int i;

    // validate arguments
    if (conp == NULL || conp->connected == 0 || tabp == NULL ||
        tabp->tabname == NULL || deld == NULL)
        return (ERR_SCM_INVALARG);
    if (deld->vald == 0)
    {
        sta = valcols(conp, tabp, deld);
        if (sta < 0)
            return (sta);
        deld->vald = 1;
    }
    // glean the length of the statement
    leen += strlen(tabp->tabname);
    for (i = 0; i < deld->nused; i++)
    {
        leen += strlen(deld->vec[i].column) + 2;
        leen += 2 * strlen(deld->vec[i].value) + 9;
    }
    // construct the DELETE statement
    conp->mystat.tabname = tabp->hname;
    stmt = (char *)calloc(leen, sizeof(char));
    if (stmt == NULL)
        return (ERR_SCM_NOMEM);
    (void)snprintf(stmt, leen, "DELETE FROM %s", tabp->tabname);
    if (deld != NULL)
    {
        wsta = strwillfit(stmt, leen, wsta, " WHERE ");
        if (wsta >= 0)
            wsta = strwillfit(stmt, leen, wsta, deld->vec[0].column);
        if (wsta >= 0)
            wsta = strwillfit(stmt, leen, wsta, "=\"");
        if (wsta >= 0)
            wsta += mysql_escape_string(stmt + wsta, deld->vec[0].value,
                                        strlen(deld->vec[0].value));
        if (wsta >= 0)
            wsta = strwillfit(stmt, leen, wsta, "\"");
        if (wsta < 0)
        {
            free((void *)stmt);
            return (wsta);
        }
        for (i = 1; i < deld->nused; i++)
        {
            wsta = strwillfit(stmt, leen, wsta, " AND ");
            if (wsta >= 0)
                wsta = strwillfit(stmt, leen, wsta, deld->vec[i].column);
            if (wsta >= 0)
                wsta = strwillfit(stmt, leen, wsta, "=\"");
            if (wsta >= 0)
                wsta += mysql_escape_string(stmt + wsta, deld->vec[i].value,
                                            strlen(deld->vec[i].value));
            if (wsta >= 0)
                wsta = strwillfit(stmt, leen, wsta, "\"");
            if (wsta < 0)
            {
                free((void *)stmt);
                return (wsta);
            }
        }
    }
    wsta = strwillfit(stmt, leen, wsta, ";");
    if (wsta < 0)
    {
        free((void *)stmt);
        return (wsta);
    }
    // execute the DELETE statement
    sta = statementscm_no_data(conp, stmt);
    free((void *)stmt);
    return (sta);
}

/*
 * Set the flags value on a match corresponding to a search criterion.
 * 
 * This function returns 0 on success and a negative error code on failure. 
 */

int setflagsscm(
    scmcon * conp,
    scmtab * tabp,
    scmkva * where,
    unsigned int flags)
{
    char *stmt;
    int leen = 128;
    int wsta = (-1);
    int sta;
    int i;

    if (conp == NULL || conp->connected == 0 || tabp == NULL ||
        tabp->tabname == NULL || where == NULL)
        return (ERR_SCM_INVALARG);
    // compute the size of the statement
    leen += strlen(tabp->tabname);
    for (i = 0; i < where->nused; i++)
    {
        leen += strlen(where->vec[i].column) + 7;
        leen += 2 * strlen(where->vec[i].value) + 3;
    }
    stmt = (char *)calloc(leen, sizeof(char));
    if (stmt == NULL)
        return (ERR_SCM_NOMEM);
    (void)snprintf(stmt, leen, "UPDATE %s SET flags=%u WHERE ", tabp->tabname,
                   flags);
    wsta = strwillfit(stmt, leen, wsta, where->vec[0].column);
    if (wsta >= 0)
        wsta = strwillfit(stmt, leen, wsta, "=\"");
    if (wsta >= 0)
        wsta += mysql_escape_string(stmt + wsta, where->vec[0].value,
                                    strlen(where->vec[0].value));
    if (wsta >= 0)
        wsta = strwillfit(stmt, leen, wsta, "\"");
    if (wsta < 0)
    {
        free((void *)stmt);
        return (wsta);
    }
    for (i = 1; i < where->nused; i++)
    {
        wsta = strwillfit(stmt, leen, wsta, " AND ");
        if (wsta >= 0)
            wsta = strwillfit(stmt, leen, wsta, where->vec[i].column);
        if (wsta >= 0)
            wsta = strwillfit(stmt, leen, wsta, "=\"");
        if (wsta >= 0)
            wsta += mysql_escape_string(stmt + wsta, where->vec[i].value,
                                        strlen(where->vec[i].value));
        if (wsta >= 0)
            wsta = strwillfit(stmt, leen, wsta, "\"");
        if (wsta < 0)
        {
            free((void *)stmt);
            return (wsta);
        }
    }
    sta = statementscm_no_data(conp, stmt);
    free((void *)stmt);
    return (sta);
}

/*
 * Convert a binary array into a hex string. Allocates memory. 
 */

char *hexify(
    int bytelen,
    void *ptr,
    int useox)
{
    unsigned char *inptr;
    char *aptr;
    char *outptr;
    int left;
    int i;

    left = bytelen + bytelen + 24;
    aptr = (char *)calloc(left, sizeof(char));
    if (aptr == NULL)
        return (NULL);
    inptr = (unsigned char *)ptr;
    outptr = aptr;
    switch (useox)
    {
    case HEXIFY_NO:
        break;
    case HEXIFY_X:
        *outptr++ = '0';
        left--;
        *outptr++ = 'x';
        left--;
        break;
    case HEXIFY_HAT:
        *outptr++ = '^';
        left--;
        *outptr++ = 'x';
        left--;
        break;
    default:
        free(aptr);
        return NULL;
    }
    if (bytelen == 0)
        *outptr++ = '0', left--;
    for (i = 0; i < bytelen; i++)
    {
        (void)snprintf(outptr, left, "%2.2x", *inptr);
        outptr += 2;
        left -= 2;
        inptr++;
    }
    *outptr = 0;
    return (aptr);
}

/*
 * Convert a hex string into a byte array. Allocates memory. The string must
 * not begin with 0x or ^x. 
 */

void *unhexify(
    int strnglen,
    char *strng)
{
    unsigned char *oot;
    unsigned int x;
    char three[3];
    int outlen;
    int i;

    if (strng == NULL)
        return NULL;
    if (strnglen <= 0 || (strnglen % 2) == 1)
        return NULL;
    outlen = strnglen / 2;
    oot = (unsigned char *)calloc(outlen, sizeof(unsigned char));
    if (oot == NULL)
        return NULL;
    three[2] = 0;
    for (i = 0; i < outlen; i++)
    {
        three[0] = strng[2 * i];
        three[1] = strng[1 + (2 * i)];
        x = 0;
        if (sscanf(three, "%x", &x) != 1 || x >= 256)
        {
            free((void *)oot);
            return NULL;
        }
        oot[i] = (unsigned char)x;
    }
    return oot;
}

/*
 * This very specific function updates the sninuse and snlist entries on a CRL 
 * using the local_id as the where criterion. 
 */

int updateblobscm(
    scmcon * conp,
    scmtab * tabp,
    uint8_t *snlist,
    unsigned int sninuse,
    unsigned int snlen,
    unsigned int lid)
{
    char *stmt;
    char *hexi;
    int leen = 128;
    int sta;

    if (conp == NULL || conp->connected == 0 || tabp == NULL ||
        tabp->tabname == NULL)
        return (ERR_SCM_INVALARG);
    hexi = hexify(snlen * SER_NUM_MAX_SZ, (void *)snlist, HEXIFY_X);
    if (hexi == NULL)
        return (ERR_SCM_NOMEM);
    // compute the size of the statement
    leen += strlen(hexi);
    stmt = (char *)calloc(leen, sizeof(char));
    if (stmt == NULL)
        return (ERR_SCM_NOMEM);
    (void)snprintf(stmt, leen,
                   "UPDATE %s SET sninuse=%u, snlist=%s WHERE local_id=%u;",
                   tabp->tabname, sninuse, hexi, lid);
    sta = statementscm_no_data(conp, stmt);
    free((void *)stmt);
    free((void *)hexi);
    return (sta);
}

/*
 * This specialized function updates the appropriate xx_last field in the
 * metadata table for the indicated time when the client completed. 
 */

int updateranlastscm(
    scmcon * conp,
    scmtab * mtab,
    char what,
    char *now)
{
    char stmt[256];
    char *ent;
    int sta;

    if (conp == NULL || conp->connected == 0 || now == NULL || now[0] == 0)
        return (ERR_SCM_INVALARG);
    switch (what)
    {
    case 'r':
    case 'R':
        ent = "rs_last";
        break;
    case 'g':
    case 'G':
        ent = "gc_last";
        break;
    case 'q':
    case 'Q':
        ent = "qu_last";
        break;
    case 'c':
    case 'C':
        ent = "ch_last";
        break;
    default:
        return (ERR_SCM_INVALARG);
    }
    (void)snprintf(stmt, sizeof(stmt),
                   "UPDATE %s SET %s=\"%s\" WHERE local_id=1;", mtab->tabname,
                   ent, now);
    sta = statementscm_no_data(conp, stmt);
    return (sta);
}
