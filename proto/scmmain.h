/*
  $Id$
*/

#ifndef _SCMMAIN_H_
#define _SCMMAIN_H_

#ifdef SCM_DEFINED_HERE

/*
  The DSN name is used to connect to the DB. This is only a part
  of the DSN; to construct the full DSN you must append the DB
  name and the user name.
*/

static char *APKI_DSN = "{MyODBC 3.51 Driver DSN};SERVER=localhost";

/*
  The database name itself.
*/

static char *APKI_DB = "apki";

/*
  The database user name.
*/

static char *APKI_DBUSER = "mysql";

/*
  Table definitions
*/

static scmtab scmtabbuilder[] = 
  {
    {				/* APKI_CERT */
      "apki_cert",
      "CERTIFICATE",
      "filename VARCHAR(255) NOT NULL,"
      "dir_id   INT UNSIGNED NOT NULL DEFAULT 1,"
      "dn       TEXT,"
      "sn       BIGINT,"
      "flags    INT UNSIGNED DEFAULT 0,"
      "ski      VARCHAR(100) NOT NULL,"
      "aki      VARCHAR(100),"
      "sia      TEXT,"
      "aia      TEXT,"
      "crldp    TEXT,"
      "valfrom  DATETIME,"
      "valto    DATETIME,"
      "ts_cur   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
      "ts_mod   TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
      "other_id INT UNSIGNED DEFAULT 0,"
      "         PRIMARY KEY (filename, dir_id),"
      "         KEY ski (ski)",
      NULL,
      0
    },
    {				/* APKI_CRL */
      "apki_crl",
      "CRL",
      "blah",
      NULL,
      0
    },
    {				/* APKI_ROA */
      "apki_roa",
      "ROA",
      "blah2",
      NULL,
      0
    },
    {				/* APKI_DIR */
      "apki_dir",
      "DIRECTORY",
      "blah3",
      NULL,
      0
    },
    {				/* APKI_METADATA */
      "apki_metadata",
      "METADATA",
      "blah4",
      NULL,
      0
    },
  } ;

#endif

#endif
