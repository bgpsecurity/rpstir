CREATE TABLE `rpki_cert` (
  `filename` varchar(256) NOT NULL,
  `dir_id` int(10) unsigned NOT NULL DEFAULT '1',
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
  `hash` varchar(256) DEFAULT NULL,
  `valfrom` datetime NOT NULL,
  `valto` datetime NOT NULL,
  `sigval` int(10) unsigned DEFAULT '0',
  `ipblen` int(10) unsigned DEFAULT '0',
  `ipb` blob,
  `ts_mod` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `local_id` int(10) unsigned NOT NULL,
  PRIMARY KEY (`filename`,`dir_id`),
  UNIQUE KEY `local_id` (`local_id`),
  KEY `ski` (`ski`,`subject`),
  KEY `aki` (`aki`,`issuer`),
  KEY `lid` (`local_id`),
  KEY `sig` (`sig`),
  KEY `isn` (`issuer`,`sn`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `rpki_crl` (
  `filename` varchar(256) NOT NULL,
  `dir_id` int(10) unsigned NOT NULL DEFAULT '1',
  `issuer` varchar(512) NOT NULL,
  `last_upd` datetime NOT NULL,
  `next_upd` datetime NOT NULL,
  `crlno` bigint(20) DEFAULT '0',
  `aki` varchar(128) DEFAULT NULL,
  `sig` varchar(520) NOT NULL,
  `hash` varchar(256) DEFAULT NULL,
  `snlen` int(10) unsigned DEFAULT '0',
  `sninuse` int(10) unsigned DEFAULT '0',
  `snlist` mediumblob,
  `flags` int(10) unsigned DEFAULT '0',
  `local_id` int(10) unsigned NOT NULL,
  PRIMARY KEY (`filename`,`dir_id`),
  UNIQUE KEY `local_id` (`local_id`),
  KEY `issuer` (`issuer`),
  KEY `aki` (`aki`),
  KEY `sig` (`sig`),
  KEY `lid` (`local_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `rpki_cta` (
  `filename` varchar(256) NOT NULL,
  `dir_id` int(10) unsigned NOT NULL DEFAULT '1',
  `ski_rta` varchar(128) NOT NULL,
  `ski_ee` varchar(128) NOT NULL,
  `hash` varchar(256) DEFAULT NULL,
  `flags` int(10) unsigned DEFAULT '0',
  `local_id` int(10) unsigned NOT NULL,
  PRIMARY KEY (`filename`,`dir_id`),
  UNIQUE KEY `local_id` (`local_id`),
  KEY `lid` (`local_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `rpki_dir` (
  `dirname` varchar(4096) NOT NULL,
  `dir_id` int(10) unsigned NOT NULL,
  PRIMARY KEY (`dir_id`),
  KEY `dirname` (`dirname`(767))
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `rpki_manifest` (
  `filename` varchar(256) NOT NULL,
  `dir_id` int(10) unsigned NOT NULL DEFAULT '1',
  `ski` varchar(128) NOT NULL,
  `hash` varchar(256) DEFAULT NULL,
  `this_upd` datetime NOT NULL,
  `next_upd` datetime NOT NULL,
  `cert_id` int(10) unsigned NOT NULL,
  `files` mediumblob,
  `fileslen` int(10) unsigned DEFAULT '0',
  `flags` int(10) unsigned DEFAULT '0',
  `local_id` int(10) unsigned NOT NULL,
  PRIMARY KEY (`filename`,`dir_id`),
  UNIQUE KEY `local_id` (`local_id`),
  KEY `lid` (`local_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

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

CREATE TABLE `rpki_roa` (
  `filename` varchar(256) NOT NULL,
  `dir_id` int(10) unsigned NOT NULL DEFAULT '1',
  `ski` varchar(128) NOT NULL,
  `sig` varchar(520) NOT NULL,
  `sigval` int(10) unsigned DEFAULT '0',
  `hash` varchar(256) DEFAULT NULL,
  `ip_addrs` varchar(32768) NOT NULL,
  `asn` int(10) unsigned NOT NULL,
  `flags` int(10) unsigned DEFAULT '0',
  `local_id` int(10) unsigned NOT NULL,
  PRIMARY KEY (`filename`,`dir_id`),
  UNIQUE KEY `local_id` (`local_id`),
  KEY `asn` (`asn`),
  KEY `sig` (`sig`),
  KEY `lid` (`local_id`),
  KEY `ski` (`ski`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `rtr_full` (
  `serial_num` int(10) unsigned NOT NULL,
  `asn` int(10) unsigned NOT NULL,
  `ip_addr` varchar(50) NOT NULL,
  PRIMARY KEY (`serial_num`,`asn`,`ip_addr`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `rtr_incremental` (
  `serial_num` int(10) unsigned NOT NULL,
  `is_announce` tinyint(1) NOT NULL,
  `asn` int(10) unsigned NOT NULL,
  `ip_addr` varchar(50) NOT NULL,
  PRIMARY KEY (`serial_num`,`asn`,`ip_addr`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `rtr_session` (
  `session_id` smallint(5) unsigned NOT NULL,
  PRIMARY KEY (`session_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `rtr_simulation_count` (
  `col` tinyint(4) DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE `rtr_update` (
  `serial_num` int(10) unsigned NOT NULL,
  `prev_serial_num` int(10) unsigned DEFAULT NULL,
  `create_time` datetime NOT NULL,
  `has_full` tinyint(1) NOT NULL,
  PRIMARY KEY (`serial_num`),
  UNIQUE KEY `prev_serial_num` (`prev_serial_num`),
  KEY `create_time` (`create_time`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
