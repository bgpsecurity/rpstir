#ifndef LIB_RPKI_SCMF_H
#define LIB_RPKI_SCMF_H

#include <inttypes.h>
#include <unistd.h>
#include <sql.h>
#include <sqlext.h>
#include "scm.h"

typedef struct _scmstat         /* connection statistics */
{
    char *errmsg;               /* error messages */
    char *tabname;              /* name of table having error: not allocated */
    int emlen;                  /* alloc'd length of errmsg */
    int rows;                   /* rows changed */
} scmstat;

typedef struct _stmtstk {
    SQLHSTMT hstmt;
    struct _stmtstk *next;
} stmtstk;

typedef struct _scmcon          /* connection info */
{
    SQLHENV henv;               /* environment handle */
    SQLHDBC hdbc;               /* database handle */
    // SQLHSTMT hstmt; /* statement handle */
    stmtstk *hstmtp;            /* stack of statement handles */
    int connected;              /* are we connected? */
    scmstat mystat;             /* statistics and errors */
} scmcon;

typedef struct _scmkv           /* used for a single column of an insert */
{
    char *column;               /* column name */
    char *value;                /* value for that column */
} scmkv;

typedef struct _scmkva          /* used for an insert */
{
    scmkv *vec;                 /* array of column/value pairs */
    int ntot;                   /* total length of "vec" */
    int nused;                  /* number of elements of "vec" in use */
    int vald;                   /* struct already validated? */
} scmkva;

typedef struct _scmsrch         /* used for a single column of a search */
{
    int colno;                  /* column number in result, typically idx+1 */
    int sqltype;                /* SQL C type, e.q. SQL_C_ULONG */
    char *colname;              /* name of column */
    void *valptr;               /* where the value goes */
    unsigned valsize;           /* expected value size */
    SQLLEN avalsize;               /* actual value size */
} scmsrch;

typedef struct _scmsrcha        /* used for a search (select) */
{
    scmsrch *vec;               /* array of column info */
    char *sname;                /* unique name for this search (can be NULL) */
    int ntot;                   /* total length of "vec" */
    int nused;                  /* number of elements in vec */
    int vald;                   /* struct already validated? */
    scmkva *where;              /* optional "where" conditionals */
    char *wherestr;             /* optional "where" string */
    void *context;              /* context to be passed from callback */
} scmsrcha;

/**
 * @brief
 *     callback function signature for a count of search results
 */
typedef int (
    *sqlcountfunc)(
    scmcon *conp,
    scmsrcha *s,
    ssize_t cnt);

/**
 * @brief
 *     callback function signature for a single search result
 */
typedef int (
    *sqlvaluefunc)(
    scmcon *conp,
    scmsrcha *s,
    ssize_t idx);

// bitfields for how to do a search

#define SCM_SRCH_DOCOUNT         0x1    /* call count func */
#define SCM_SRCH_DOVALUE_ANN     0x2    /* call val func if all vals non-NULL */
#define SCM_SRCH_DOVALUE_SNN     0x4    /* call val func if some vals non-NULL
                                         */
#define SCM_SRCH_DOVALUE_ALWAYS  0x8    /* always call value func */
#define SCM_SRCH_DOVALUE         0xE    /* call value func */
#define SCM_SRCH_BREAK_CERR      0x10   /* break from loop if count func err */
#define SCM_SRCH_BREAK_VERR      0x20   /* break from loop if value func err */
#define SCM_SRCH_DO_JOIN         0x40   /* Include join with directory table */
#define SCM_SRCH_DO_JOIN_CRL     0x80   /* Include join with crl table */
// Notes on join_self: (1) The table is aliases as t1 and t2.
// (2) The wherestr should also include the on clause with the format
// "%s\n%s", onString, whereString
#define SCM_SRCH_DO_JOIN_SELF    0x100  /* Include join with self */


#define WHERESTR_SIZE 1024

#ifndef SQLOK
#define SQLOK(s) (s == SQL_SUCCESS || s == SQL_SUCCESS_WITH_INFO)
#endif

/*
 * Initialize a connection to the named DSN. Return a connection object on
 * success and a negative error code on failure.
 */
extern scmcon *connectscm(
    char *dsnp,
    char *errmsg,
    int emlen);

/*
 * Create a new empty srch array
 */
extern scmsrcha *newsrchscm(
    char *name,
    int leen,
    int cleenn,
    int useWhereStr);

/*
 * add clause for testing the value of a flag to a where string
 */
extern void addFlagTest(
    char *whereStr,
    int flagVal,
    int isSet,
    int needAnd);

/*
 * Disconnect from a DSN and free all memory.
 */
extern void disconnectscm(
    scmcon *conp);

/*
 * Free all the memory in a search array
 */
extern void freesrchscm(
    scmsrcha *srch);

/*
 * Convert a hex string into a byte array. Allocates memory. The string must
 * not begin with 0x or ^x.
 */
extern void *unhexify(
    int strnglen,
    char const *strng);

/*
 * Get the error message from a connection.
 */
extern char *geterrorscm(
    scmcon *conp);

/*
 * Get the name of the table that had an error.
 */
extern char *gettablescm(
    scmcon *conp);

/*
 * Convert a binary array into a hex string. Allocates memory.
 */
extern char *hexify(
    int bytelen,
    void const *bytes,
    int useox);

/*
 * Get the number of rows returned by a statement.
 */
extern int getrowsscm(
    scmcon *conp);

/*
 * Execute an SQL statement.
 *
 * Before calling statementscm: You must call newhstmt(conp) and verify its
 * return value.
 *
 * After calling statementscm and using its statement handle: You must call
 * pophstmt(conp).
 */
extern int statementscm(
    scmcon *conp,
    char *stm);

/**
 * @brief
 *     Execute a SQL statement, ignoring any returned rows.
 */
extern int statementscm_no_data(
    scmcon *conp,
    char *stm);

/*
 * Create a database and grant the mysql default user the standard set of
 * privileges for that database.
 */
extern int createdbscm(
    scmcon *conp,
    char *dbname,
    char *dbuser);

/*
 * Delete a database.
 */
extern int deletedbscm(
    scmcon *conp,
    char *dbname);

/*
 * Create all the tables listed in scmp. This assumes that the database has
 * already been created through a call to createdbscm().
 */
extern int createalltablesscm(
    scmcon *conp,
    scm *scmp);

/**
 * @brief
 *     Insert an entry into a database table.
 */
extern int insertscm(
    scmcon *conp,
    scmtab *tabp,
    scmkva *arr);

/*
 * Get the maximum of the specified id field of the given table.  If table is
 * empty, then sets *ival to 0.
 */
extern int getmaxidscm(
    scm *scmp,
    scmcon *conp,
    char *field,
    scmtab *mtab,
    unsigned int *ival);

extern int getuintscm(
    scmcon *conp,
    unsigned int *ival);

/**
 * @brief
 *     searches in a database table for entries that match the stated
 *     search criteria
 *
 * Note that searchscm() can be called recursively, so that there can
 * be more than one cursor open at a time.  For this reason,
 * searchscm() must create its own STMT and then destroy it when it is
 * done.
 */
extern int searchscm(
    scmcon *conp,
    scmtab *tabp,
    scmsrcha *srch,
    sqlcountfunc cnter,
    sqlvaluefunc valer,
    int what,
    char *orderp);

/*
 * Add a new column to a search array. Note that this function does not grow
 * the size of the column array, so enough space must have already been
 * allocated when the array was created.
 */
extern int addcolsrchscm(
    scmsrcha *srch,
    char *colname,
    int sqltype,
    unsigned valsize);

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
extern int searchorcreatescm(
    scm *scmp,
    scmcon *conp,
    scmtab *tabp,
    scmsrcha *srch,
    scmkva *ins,
    unsigned int *idp);

/**
 * @brief
 *     deletes entries in a database table that match the stated search criteria
 */
extern int deletescm(
    scmcon *conp,
    scmtab *tabp,
    scmkva *deld);

/*
 * Set the flags value on a match corresponding to a search criterion.
 *
 * This function returns 0 on success and a negative error code on failure.
 */
extern int setflagsscm(
    scmcon *conp,
    scmtab *tabp,
    scmkva *where,
    unsigned int flags);

/*
 * This very specific function updates the sninuse and snlist entries on a CRL
 * using the local_id as the where criterion.
 */
extern int updateblobscm(
    scmcon *conp,
    scmtab *tabp,
    uint8_t *snlist,
    unsigned int sninuse,
    unsigned int snlen,
    unsigned int lid);

/*
 * This specialized function updates the appropriate xx_last field in the
 * metadata table for the indicated time when the client completed.
 */
extern int updateranlastscm(
    scmcon *conp,
    scmtab *mtab,
    char what,
    char *now);

/*
 * Create a new STMT and push it onto the top of the stack of STMTs in the
 * connection.
 */
extern SQLRETURN newhstmt(
    scmcon *conp);

/*
 * Pop the top element off the hstmt stack of a connection, free the hstmt and
 * the associated memory.
 */
extern void pophstmt(
    scmcon *conp);

/*
 * Directives for hexify()
 */

#define HEXIFY_NO         0     // no prefix
#define HEXIFY_X          1     // 0x prefix
#define HEXIFY_HAT        2     // ^x prefix

/*
 * Macros
 */

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(A) ((void)A)
#endif

#endif
