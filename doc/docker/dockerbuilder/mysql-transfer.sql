use rpstir;

CREATE TABLE `rpki_link_rpvc` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `protocol` varchar(64) NOT NULL COMMENT 'http或https',
  `address` varchar(64) NOT NULL COMMENT 'IP地址或域名地址',
  `port`    int(10) unsigned NOT NULL COMMENT '地址端口',
  `style`   varchar(64) NOT NULL COMMENT '类型: vc/rp',
  `create_time` datetime NOT NULL COMMENT '创建时间',
  `state` varchar(16) NOT NULL DEFAULT 'valid'  COMMENT 'valid为有效，invalid为无效',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8 COLLATE=utf8_bin comment='相邻者配置表，有可能是vc，有可能是rp';


CREATE TABLE `rpki_link_rpvc_log` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `link_id` int(10) unsigned NOT NULL  COMMENT '对应的rpki_linked_rpvc_config的id',
  `update_type`   varchar(64) NOT NULL COMMENT '类型: all/update,全量还是增量',
  `update_time` datetime NOT NULL COMMENT '更新时间',
  `serial_num` int(10)   COMMENT '增量更新时的serialnum，全量时为空',
  `result`   varchar(64) COMMENT '更新结果: ok/fail',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8 COLLATE=utf8_bin comment='相邻者日志，更新记录';



									 
'RP数据库 添加VC地址									 
insert into rpki_link_rpvc(protocol,address,port,style,create_time,state) 
									 values ('https','202.173.14.103','8444','vc','2019-03-12 1:1:1','valid');

'VC数据库，添加RP地址
insert into rpki_link_rpvc(protocol,address,port,style,create_time,state) 
									 values ('https','202.173.14.102','8443','rp','2019-03-12 1:1:1','valid');									 									 
									 
									 
									 
									 
