/*
  $Id$
*/

#ifndef _SCM_H_
#define _SCM_H_

/*
  The DSN name is used to connect to the DB. This is only a part
  of the DSN; to construct the full DSN you must append the DB
  name and the user name.
*/

static char *APKI_DSN =
  "{MyODBC 3.51 Driver DSN};SERVER=localhost";

/*
  The database name itself.
*/

static char *APKI_DB =
  "APKI";

/*
  The database user name.
*/

static char *APKI_DBUSER =
  "mysql";

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

static char *APKI_CERT_COLS[] = { "blah", "foo" } ;

static scmtab APKI_CERT =
  {
    "apki_cert",
    "CERTIFICATE",
    "",
    APKI_CERT_COLS,
    2
  } ;

static char *APKI_CRL_COLS[] = { "fred" "barney", "wilma", "betty" };

static scmtab APKI_CRL =
  {
    "apki_crl",
    "CRL",
    "",
    APKI_CRL_COLS,
    4
  } ;

/*
  This structure defines the overall database schema
*/

typedef struct _scm
{
  char   *dsn;			/* canonical data source name from .dsn section */
  scmtab *tables;		/* array of tables */
  int     ntables;		/* number of tables in "tables" */
} scm;

#endif
