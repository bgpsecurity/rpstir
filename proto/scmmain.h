/*
  $Id$
*/

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  David Montana, Mark Reynolds
 *
 * ***** END LICENSE BLOCK ***** */

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
  The database name itself.  It can be overridden via the
  environment variable APKI_DB
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
  identifier with the new one obtained via max(local_id) + 1
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
      "sig      VARCHAR(520) NOT NULL,"
      "valfrom  DATETIME NOT NULL,"
      "valto    DATETIME NOT NULL,"
      "ipblen   INT UNSIGNED DEFAULT 0,"
      "ipb      BLOB,"
      "ts_mod   TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
      "local_id INT UNSIGNED NOT NULL UNIQUE,"
      "         PRIMARY KEY (filename, dir_id),"
      "         KEY ski (ski, subject),"
      "         KEY aki (aki, issuer),"
      "         KEY lid (local_id),"
      "         KEY sig (sig),"
      "         KEY isn (issuer, sn)",
      NULL,
      0
    },
    {				/* APKI_CRL */
/*
  Usage notes: this_upd and next_upd are stored in GMT. local_id is a
  unique identifier obtained as max(local_id) + 1
  issuer is the actual CRL issuer, obtained from the issuer field of
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
      "aki      VARCHAR(128),"
      "sig      VARCHAR(520) NOT NULL,"
      "snlen    INT UNSIGNED DEFAULT 0,"
      "sninuse  INT UNSIGNED DEFAULT 0,"
      "snlist   MEDIUMBLOB,"
      "flags    INT UNSIGNED DEFAULT 0,"
      "local_id INT UNSIGNED NOT NULL UNIQUE,"
      "         PRIMARY KEY (filename, dir_id),"
      "         KEY issuer (issuer),"
      "         KEY aki (aki),"
      "         KEY sig (sig),"
      "         KEY lid (local_id)",
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
      "sig      VARCHAR(520) NOT NULL,"
      "ip_addrs VARCHAR(32768) NOT NULL,"
      "asn      INT UNSIGNED NOT NULL,"
      "flags    INT UNSIGNED DEFAULT 0,"
      "local_id INT UNSIGNED NOT NULL UNIQUE,"
      "         PRIMARY KEY (filename, dir_id),"
      "         KEY asn (asn),"
      "         KEY sig (sig),"
      "         KEY lid (local_id),"
      "         KEY ski (ski)",
      NULL,
      0
    },
    {				/* APKI_MANIFEST */
      "apki_manifest",
      "MANIFEST",
      "filename VARCHAR(256) NOT NULL,"
      "dir_id   INT UNSIGNED NOT NULL DEFAULT 1,"
      "ski      VARCHAR(128) NOT NULL,"
      "this_upd DATETIME NOT NULL,"
      "next_upd DATETIME NOT NULL,"
      "cert_id  INT UNSIGNED NOT NULL,"
      "files    MEDIUMBLOB,"
      "flags    INT UNSIGNED DEFAULT 0,"
      "local_id INT UNSIGNED NOT NULL UNIQUE,"
      "         PRIMARY KEY (filename, dir_id),"
      "         KEY lid (local_id)",
      NULL,
      0
    },
    {				/* APKI_DIR */
      "apki_dir",
      "DIRECTORY",
      "dirname  VARCHAR(4096) NOT NULL,"
      "dir_id   INT UNSIGNED NOT NULL,"
      "         PRIMARY KEY (dir_id),"
      "         KEY dirname (dirname)",
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
      "ch_last  TIMESTAMP DEFAULT 0,"
      "flags    INT UNSIGNED DEFAULT 0,"
      "local_id INT UNSIGNED DEFAULT 1,"
      "         PRIMARY KEY (local_id)",
      NULL,
      0
    },

	// these tables really should be specified in the server
	//   directory, but there was no good way to do that and not
	//   risk them not being created at initialization

	{             /* RTR_UPDATE */
	  "rtr_update",
	  "RTR_UPDATE",
	  "serial_num  INT UNSIGNED NOT NULL UNIQUE,"
	  "create_time DATETIME NOT NULL,"
	  "            PRIMARY KEY (serial_num)",
	  NULL,
	  0
	},
	{            /* RTR_FULL */
	  "rtr_full",
	  "RTR_FULL",
	  "serial_num  INT UNSIGNED NOT NULL,"
	  "roa_filename VARCHAR(256) NOT NULL,"
	  "asn         INT UNSIGNED NOT NULL,"
	  "ip_addr     VARCHAR(50) NOT NULL,"
	  "KEY asn (asn), KEY ip_addr (ip_addr)",
	  NULL,
	  0
	},
	{            /* RTR_INCREMENTAL */
	  "rtr_incremental",
	  "RTR_INCREMENTAL",
	  "serial_num  INT UNSIGNED NOT NULL,"
	  "is_announce BOOLEAN NOT NULL,"
	  "asn         INT UNSIGNED NOT NULL,"
	  "ip_addr     VARCHAR(50) NOT NULL,"
	  "KEY asn (asn), KEY ip_addr (ip_addr)",
	  NULL,
	  0
	},
  } ;

#endif

#endif
