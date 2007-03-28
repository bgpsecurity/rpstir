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
/*
  Usage notes: valfrom and valto are stored in GMT. local_id is a unique
  identifier obtained from the cert_max field of the metadata table. When a
  new cert is to be inserted, the following algorithm is used: obtain cert_max,
  increment it, set local_id to that incremented value, insert the cert, update
  cert_max to be the new, incremented value. Thus, cert_max always contains
  the largest id that is actually in use.
*/
      "apki_cert",
      "CERTIFICATE",
      "filename VARCHAR(256) NOT NULL,"
      "dir_id   INT UNSIGNED NOT NULL DEFAULT 1,"
      "subject  VARCHAR(512),"
      "issuer   VARCHAR(512) NOT NULL,"
      "sn       BIGINT NOT NULL,"
      "flags    INT UNSIGNED DEFAULT 0,"
      "ski      VARCHAR(128) NOT NULL,"
      "aki      VARCHAR(128),"
      "sia      VARCHAR(1024),"
      "aia      VARCHAR(1024),"
      "crldp    VARCHAR(1024),"
      "valfrom  DATETIME NOT NULL,"
      "valto    DATETIME NOT NULL,"
      "ts_mod   TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
      "local_id INT UNSIGNED NOT NULL UNIQUE,"
      "other_id INT UNSIGNED DEFAULT 0,"
      "other_ty INT UNSIGNED DEFAULT 0,"
      "         PRIMARY KEY (filename, dir_id),"
      "         KEY ski (ski),"
      "         KEY isn (issuer, sn)",
      NULL,
      0
    },
    {				/* APKI_CRL */
/*
  Usage notes: this_upd and next_upd are stored in GMT. local_id is a unique
  identifier obtained from the crl_max field of the metadata table (see above
  under the cert usage notes for the algorithm used in calculating the crl
  local_id). issuer is the actual CRL issuer, obtained from the issuer field of
  the CRL (direct CRL). snlist is the list of serial numbers for this issuer.
  It is an array of bignums. The number of bignums in the list is snlen. Some
  of these revocations may already have happened and the corresponding sn set
  to 0 in the list. sninuse keeps track of the  number of serial numbers that
  are not zero in the list.  When this number drops to 0, the entire CRL may be
  deleted from the DB.

  Note that snlist is of type MEDIUMBLOB, indicating that it can hold at most
  16M/8 = 2M entries.
*/
      "apki_crl",
      "CRL",
      "filename VARCHAR(256) NOT NULL,"
      "dir_id   INT UNSIGNED NOT NULL DEFAULT 1,"
      "issuer   VARCHAR(512) NOT NULL,"
      "last_upd DATETIME NOT NULL,"
      "next_upd DATETIME NOT NULL,"
      "crlno    BIGINT DEFAULT 0,"
      "snlen    INT UNSIGNED DEFAULT 0,"
      "sninuse  INT UNSIGNED DEFAULT 0,"
      "snlist   MEDIUMBLOB,"
      "flags    INT UNSIGNED DEFAULT 0,"
      "local_id INT UNSIGNED NOT NULL UNIQUE,"
      "other_id INT UNSIGNED DEFAULT 0,"
      "other_ty INT UNSIGNED DEFAULT 0,"
      "         PRIMARY KEY (filename, dir_id),"
      "         KEY issuer (issuer),"
      "         KEY next_upd (next_upd)",
      NULL,
      0
    },
    {				/* APKI_ROA */
/*
  Usage notes: the ski is the ski of the signing cert, and is thus
  effectively the parent of this ROA. The asn is the AS number from
  the ROA (there is only one now, not a list). The IP address information
  is not stored here; it must be fetched from the file itself using
  the ROA read code. local_id is as with certs and crls.
*/
      "apki_roa",
      "ROA",
      "filename VARCHAR(256) NOT NULL,"
      "dir_id   INT UNSIGNED NOT NULL DEFAULT 1,"
      "ski      VARCHAR(128) NOT NULL,"
      "asn      INT UNSIGNED NOT NULL,"
      "flags    INT UNSIGNED DEFAULT 0,"
      "local_id INT UNSIGNED NOT NULL UNIQUE,"
      "other_id INT UNSIGNED DEFAULT 0,"
      "other_ty INT UNSIGNED DEFAULT 0,"
      "         PRIMARY KEY (filename, dir_id),"
      "         KEY asn (asn),"
      "         KEY ski (ski)",
      NULL,
      0
    },
    {				/* APKI_DIR */
      "apki_dir",
      "DIRECTORY",
      "dirname  VARCHAR(4096) NOT NULL,"
      "dir_id   INT UNSIGNED NOT NULL,"
      "         PRIMARY KEY (dir_id)",
      NULL,
      0
    },
    {				/* APKI_METADATA */
      "apki_metadata",
      "METADATA",
      "rootdir  VARCHAR(4096) NOT NULL,"
      "inited   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
      "rs_last  TIMESTAMP DEFAULT 0,"
      "qu_last  TIMESTAMP DEFAULT 0,"
      "gc_last  TIMESTAMP DEFAULT 0,"
      "flags    INT UNSIGNED DEFAULT 0,"
      "cert_max INT UNSIGNED DEFAULT 0,"
      "crl_max  INT UNSIGNED DEFAULT 0,"
      "roa_max  INT UNSIGNED DEFAULT 0,"
      "dir_max  INT UNSIGNED DEFAULT 0,"
      "local_id INT UNSIGNED DEFAULT 1,"
      "         PRIMARY KEY (local_id)",
      NULL,
      0
    },
  } ;

#endif

#endif
