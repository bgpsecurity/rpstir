set global read_only=0;
flush privileges;

use rpstir;

CREATE TABLE `rpki_link_rpvc` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `protocol` varchar(64) NOT NULL COMMENT 'http or https',
  `address` varchar(64) NOT NULL COMMENT 'IP or domain ',
  `port`    int(10) unsigned NOT NULL COMMENT 'port',
  `style`   varchar(64) NOT NULL COMMENT 'vc/rp',
  `create_time` datetime NOT NULL COMMENT 'create time',
  `state` varchar(16) NOT NULL DEFAULT 'valid'  COMMENT 'valid/invalid',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8 COLLATE=utf8_bin comment='linked rp or vc';


CREATE TABLE `rpki_link_rpvc_log` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `link_id` int(10) unsigned NOT NULL  COMMENT 'rpki_linked_rpvc_config id',
  `update_type`   varchar(64) NOT NULL COMMENT 'all/update',
  `update_time` datetime NOT NULL COMMENT 'update time',
  `serial_num` int(10)   COMMENT 'incremental is serialnum; full is empty',
  `result`   varchar(64) COMMENT 'ok/fail',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8 COLLATE=utf8_bin comment='log';



							 
insert into rpki_link_rpvc(protocol,address,port,style,create_time,state) 
									 values ('https','202.173.14.103','8444','vc','2019-03-12 1:1:1','valid');

insert into rpki_link_rpvc(protocol,address,port,style,create_time,state) 
									 values ('https','202.173.14.102','8443','rp','2019-03-12 1:1:1','valid');									 									 
									 
									 
set global read_only=1;
flush privileges;
									 
