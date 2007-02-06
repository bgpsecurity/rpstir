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
      "dn       VARCHAR(1024),"
      "sn       BIGINT,"
      "flags    INT UNSIGNED DEFAULT 0,"
      "ski      VARCHAR(100) NOT NULL,"
      "aki      VARCHAR(100),"
      "sia      VARCHAR(1024),"
      "aia      VARCHAR(1024),"
      "crldp    VARCHAR(1024),"
      "valfrom  DATETIME NOT NULL,"
      "valto    DATETIME NOT NULL,"
      "ts_cur   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
      "ts_mod   TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
      "local_id INT UNSIGNED NOT NULL UNIQUE,"
      "other_id INT UNSIGNED DEFAULT 0,"
      "other_ty INT UNSIGNED DEFAULT 0,"
      "         PRIMARY KEY (filename, dir_id),"
      "         KEY ski (ski)",
      NULL,
      0
    },
    {				/* APKI_CRL */
      "apki_crl",
      "CRL",
      "filename VARCHAR(255) NOT NULL,"
      "dir_id   INT UNSIGNED NOT NULL DEFAULT 1,"
      "issuer   VARCHAR(255) NOT NULL,"
      "this_upd DATETIME NOT NULL,"
      "next_upd DATETIME NOT NULL,"
      "flags    INT UNSIGNED DEFAULT 0,"
      "local_id INT UNSIGNED NOT NULL UNIQUE,"
      "other_id INT UNSIGNED DEFAULT 0,"
      "other_ty INT UNSIGNED DEFAULT 0,"
      "         PRIMARY KEY (filename, dir_id),"
      "         KEY issuer (issuer),"
      "         KEY this_upd (this_upd)",
      NULL,
      0
    },
    {				/* APKI_ROA */
      "apki_roa",
      "ROA",
      "",			/* nothing defined yet */
      NULL,
      0
    },
    {				/* APKI_DIR */
      "apki_dir",
      "DIRECTORY",
      "dirname  VARCHAR(4096) NOT NULL DEFAULT '.',"
      "dir_id   INT UNSIGNED NOT NULL DEFAULT 1,"
      "         PRIMARY KEY (dir_id)",
      NULL,
      0
    },
    {				/* APKI_METADATA */
      "apki_metadata",
      "METADATA",
      "rootdir  VARCHAR(1024),"
      "inited   DATETIME,"
      "rs_last  DATETIME,"
      "qu_last  DATETIME,"
      "gc_last  DATETIME,"
      "flags    INT UNSIGNED DEFAULT 0,"
      "cert_max INT UNSIGNED DEFAULT 1,"
      "crl_max  INT UNSIGNED DEFAULT 1,"
      "roa_max  INT UNSIGNED DEFAULT 1,"
      "local_id INT UNSIGNED DEFAULT 1,"
      "         PRIMARY KEY (local_id)",
      NULL,
      0
    },
  } ;

#endif

#endif
