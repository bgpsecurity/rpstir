-- NOTE: all the tables begin with 'rpstir_'. This prefix may be configurable.

-- database-level metadata
-- current version: SELECT schema_version FROM rpstir_metadata ORDER BY installed DESC LIMIT 1;
-- on initializing or upgrading the schema to version foo: INSERT INTO rpstir_metadata (schema_version) VALUES (foo);
CREATE TABLE rpstir_metadata (
  schema_version int unsigned DEFAULT NULL, -- NULL indicates a development version with no version number
  installed timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  root_dir varchar(4096) NOT NULL,
  PRIMARY KEY (installed)
);

-- (bi)map URIs to file hashes
-- hashes are used as unique IDs for all types of rpki objects in this schema
CREATE TABLE rpstir_rpki_file (
  uri varchar(1024) NOT NULL, -- where the file was downloaded from
  hash binary(32) NOT NULL, -- sha256 maybe?, filename could be e.g. /path/to/rpki/CACHE/01/23456789abcdef...
                            -- hash maybe should be the same as the alg used by manifests?
                            -- length would be different for different choice of hash function
  downloaded datetime NOT NULL,
  file_type ENUM('cer', 'crl', 'roa') DEFAULT NULL, -- NULL indicates unrecognized
  parses boolean NOT NULL DEFAULT FALSE, -- avoid trying to reparse the same file if it fails the first time
  flags bigint unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (hash, uri), -- more useful as a constraint than for SELECT
  KEY uri (uri, downloaded), -- find latest file for a specified uri
  KEY uri_good (uri, file_type, parses, downloaded) -- find latest file of the same type that actually can be parsed for a specified uri
);

-- map internal hash to any other hash algs used in e.g. manifests
-- This should make algorithm agility somewhat more feasible in the future.
CREATE TABLE rpstir_rpki_hash (
  hash binary(32) NOT NULL, -- hash used throughout the schema
  alg ENUM('sha256') NOT NULL, -- alternate hash algorithm
  data varbinary(512) NOT NULL, -- alternate hash

  -- NOTE: these keys assume there are no hash collisions for any algorithm
  PRIMARY KEY (hash, alg), -- lookup an alternate hash based on local hash
  UNIQUE KEY (alg, data) -- lookup a local hash based on alternate hash
);

CREATE TABLE rpstir_rpki_cert_asn (
  hash binary(32) NOT NULL,
  first_asn int unsigned NOT NULL,
  last_asn int unsigned NOT NULL,
  PRIMARY KEY (hash, first_asn),
  CHECK (first_asn <= last_asn)
);

CREATE TABLE rpstir_rpki_cert_ip (
  hash binary(32) NOT NULL,
  first_ip varbinary(16) NOT NULL, -- binary encoding, network byte order
  last_ip varbinary(16) NOT NULL, -- ditto
  PRIMARY KEY (hash, first_ip),
  CHECK (length(first_ip) = 4 OR length(first_ip) = 16),
  CHECK (length(first_ip) = length(last_ip)),
  CHECK (first_ip <= last_ip)
);

CREATE TABLE rpstir_rpki_cert_aia (
  hash binary(32) NOT NULL,
  preference int unsigned NOT NULL, -- lower number is more preferred
  uri varchar(1024) NOT NULL,
  PRIMARY KEY (hash, preference)
);

CREATE TABLE rpstir_rpki_cert_sia (
  hash binary(32) NOT NULL,
  method ENUM('id-ad-caRepository', 'id-ad-rpkiManifest', 'id-ad-signedObject') NOT NULL,
  preference int unsigned NOT NULL, -- lower number is more preferred
  uri varchar(1024) NOT NULL,
  PRIMARY KEY (hash, method, preference)
);

CREATE TABLE rpstir_rpki_cert_crldp (
  hash binary(32) NOT NULL,
  uri varchar(1024) NOT NULL,
  PRIMARY KEY (hash, uri)
);

-- TODO: ask Andrew if there's anything else here to change
CREATE TABLE `rpstir_rpki_cert` (
  `hash` binary(32) NOT NULL,
  `subject` varchar(512) DEFAULT NULL,
  `issuer` varchar(512) NOT NULL,
  `sn` bigint(20) NOT NULL,
  `ski` varchar(128) NOT NULL,
  `aki` varchar(128) DEFAULT NULL,
  `sig` varchar(520) NOT NULL, -- TODO: should this be in the database?
  `valfrom` datetime NOT NULL,
  `valto` datetime NOT NULL,
  `sigval` int(10) unsigned DEFAULT '0', -- TODO: what is this?
  `ts_mod` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, -- TODO: is this needed?
  inherit_asn boolean NOT NULL DEFAULT FALSE,
  inherit_ip boolean NOT NULL DEFAULT FALSE,
  PRIMARY KEY (hash),
  KEY `ski` (`ski`,`subject`),
  KEY `aki` (`aki`,`issuer`),
  KEY `sig` (`sig`),
  KEY `isn` (`issuer`,`sn`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- TODO: should CMS EE certs just be added to rpstir_rpki_cert with the overall CMS hash instead of using this table?
CREATE TABLE rpstir_rpki_cms (
  hash binary(32) NOT NULL,
  cert_hash binary(32) NOT NULL,
  PRIMARY KEY (hash)
);

CREATE TABLE rpstir_rpki_crl_sn (
  hash binary(32) NOT NULL,
  serial bigint unsigned NOT NULL,
  revocation_date datetime NOT NULL,
  PRIMARY KEY (hash, serial)
);

-- TODO: read RFC
CREATE TABLE `rpstir_rpki_crl` (
  `hash` binary(32) NOT NULL,
  `issuer` varchar(512) NOT NULL,
  `last_upd` datetime NOT NULL,
  `next_upd` datetime NOT NULL,
  `crlno` bigint(20) DEFAULT '0',
  `aki` varchar(128) DEFAULT NULL,
  `sig` varchar(520) NOT NULL, -- TODO: should this be in the database?
  PRIMARY KEY (`hash`),
  KEY `issuer` (`issuer`),
  KEY `aki` (`aki`),
  KEY `sig` (`sig`),
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE rpstir_rpki_manifest_files (
  hash binary(32) NOT NULL,
  filename varchar(256) NOT NULL,
  file_hash_alg ENUM('sha256') NOT NULL,
  file_hash varbinary(512) NOT NULL,
  PRIMARY KEY (hash, filename)
);

-- TODO: read I-D
CREATE TABLE `rpstir_rpki_manifest` (
  `hash` binary(32) NOT NULL,
  `ski` varchar(128) NOT NULL, -- TODO: is this from the EE? if it is, it should be deleted
  `this_upd` datetime NOT NULL,
  `next_upd` datetime NOT NULL,
  `cert_hash` binary(32) NOT NULL, -- TODO: delete if reduntant with rpstir_rpki_cms.cert_hash?
  PRIMARY KEY (`hash`),
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE rpstir_prefix (
  id bigint unsigned NOT NULL AUTO_INCREMENT,
  prefix varbinary(16) NOT NULL, -- binary encoding, network byte order, filled with 0s to the full length for the address family
  prefix_length tinyint unsigned NOT NULL,
  max_prefix_length tinyint unsigned NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY (prefix, prefix_length, max_prefix_length),
  CHECK (length(prefix) = 4 OR length(prefix) = 16),
  CHECK (prefix_length <= max_prefix_length),
  CHECK (max_prefix_length <= length(prefix) * 8)
);

CREATE TABLE rpstir_rpki_roa_prefix (
  hash binary(32) NOT NULL,
  prefix_id bigint unsigned NOT NULL,
  PRIMARY KEY (hash, prefix_id)
);

-- TODO: read I-D
CREATE TABLE `rpstir_rpki_roa` (
  `hash` binary(32) NOT NULL,
  asn int unsigned NOT NULL,
  PRIMARY KEY (`hash`),
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `rpstir_rtr_full` (
  `serial_num` int(10) unsigned NOT NULL,
  `asn` int(10) unsigned NOT NULL,
  prefix_id bigint unsigned NOT NULL
  PRIMARY KEY (`serial_num`,`asn`,`prefix_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `rpstir_rtr_incremental` (
  `serial_num` int(10) unsigned NOT NULL,
  `is_announce` tinyint(1) NOT NULL,
  `asn` int(10) unsigned NOT NULL,
  prefix_id bigint unsigned NOT NULL
  PRIMARY KEY (`serial_num`,`asn`,`prefix_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `rpstir_rtr_session` (
  `session_id` smallint(5) unsigned NOT NULL,
  PRIMARY KEY (`session_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `rpstir_rtr_update` (
  `serial_num` int(10) unsigned NOT NULL,
  `prev_serial_num` int(10) unsigned DEFAULT NULL,
  `create_time` datetime NOT NULL,
  `has_full` tinyint(1) NOT NULL,
  PRIMARY KEY (`serial_num`),
  UNIQUE KEY `prev_serial_num` (`prev_serial_num`),
  KEY `create_time` (`create_time`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
