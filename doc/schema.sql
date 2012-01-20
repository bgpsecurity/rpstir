-- NOTE: all the tables begin with 'rpstir_'. This prefix may be configurable.

-- database-level metadata
-- current version: SELECT schema_version FROM rpstir_metadata ORDER BY installed DESC LIMIT 1;
-- on initializing or upgrading the schema to version foo: INSERT INTO rpstir_metadata (schema_version) VALUES (foo);
CREATE TABLE rpstir_metadata (
  schema_version int unsigned DEFAULT NULL, -- NULL indicates a development version with no version number
  installed timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
  PRIMARY KEY (hash, uri), -- more useful as a constraint than for SELECT
  KEY uri (uri, downloaded) -- find latest hash for a specified uri
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

CREATE TABLE `rpstir_rpki_cert` (
  `hash` binary(32) NOT NULL,
  `subject` varchar(512) DEFAULT NULL,
  `issuer` varchar(512) NOT NULL,
  `sn` bigint(20) NOT NULL,
  `flags` int(10) unsigned DEFAULT '0',
  `ski` varchar(128) NOT NULL,
  `aki` varchar(128) DEFAULT NULL,
  `sia` varchar(1024) DEFAULT NULL,
  `aia` varchar(1024) DEFAULT NULL,
  `crldp` varchar(1024) DEFAULT NULL,
  `sig` varchar(520) NOT NULL,
  `valfrom` datetime NOT NULL,
  `valto` datetime NOT NULL,
  `sigval` int(10) unsigned DEFAULT '0',
  `ts_mod` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (hash),
  KEY `ski` (`ski`,`subject`),
  KEY `aki` (`aki`,`issuer`),
  KEY `sig` (`sig`),
  KEY `isn` (`issuer`,`sn`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE rpstir_rpki_crl_sn (
  hash binary(32) NOT NULL,
  serial int unsigned NOT NULL, -- TODO: check type
  PRIMARY KEY (hash, serial)
);

CREATE TABLE `rpstir_rpki_crl` (
  `hash` binary(32) NOT NULL,
  `issuer` varchar(512) NOT NULL,
  `last_upd` datetime NOT NULL,
  `next_upd` datetime NOT NULL,
  `crlno` bigint(20) DEFAULT '0',
  `aki` varchar(128) DEFAULT NULL,
  `sig` varchar(520) NOT NULL,
  `flags` int(10) unsigned DEFAULT '0',
  PRIMARY KEY (`hash`),
  KEY `issuer` (`issuer`),
  KEY `aki` (`aki`),
  KEY `sig` (`sig`),
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE rpstir_rpki_manifest_files (
  hash binary(32) NOT NULL,
  filename varchar(256) NOT NULL,
  filehash binary(32) NOT NULL,
  PRIMARY KEY (hash, filename)
);

CREATE TABLE `rpstir_rpki_manifest` (
  `hash` binary(32) NOT NULL,
  `ski` varchar(128) NOT NULL,
  `this_upd` datetime NOT NULL,
  `next_upd` datetime NOT NULL,
  `cert_hash` binary(32) NOT NULL,
  `flags` int(10) unsigned DEFAULT '0',
  PRIMARY KEY (`hash`),
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- TODO: merge this table with rpki_files?
CREATE TABLE `rpki_metadata` (
  `rootdir` varchar(4096) NOT NULL,
  `inited` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `rs_last` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `qu_last` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `gc_last` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `ch_last` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `flags` int(10) unsigned DEFAULT '0',
  `local_id` int(10) unsigned NOT NULL DEFAULT '1',
  PRIMARY KEY (`local_id`)
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
  PRIMARY KEY (hash, prefix_authz_id)
);

CREATE TABLE `rpstir_rpki_roa` (
  `hash` binary(32) NOT NULL,
  `ski` varchar(128) NOT NULL,
  `sig` varchar(520) NOT NULL,
  `sigval` int(10) unsigned DEFAULT '0',
  `flags` int(10) unsigned DEFAULT '0',
  PRIMARY KEY (`hash`),
  KEY `sig` (`sig`),
  KEY `ski` (`ski`)
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
