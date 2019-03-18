set global read_only=0;
flush privileges;

SET PASSWORD FOR 'root'@'localhost' = PASSWORD('Rpstir-123');


CREATE USER 'rpstir'@'localhost' IDENTIFIED BY 'Rpstir-123';
CREATE DATABASE rpstir;
GRANT ALL PRIVILEGES ON rpstir.* TO 'rpstir'@'localhost' IDENTIFIED BY 'Rpstir-123';
GRANT ALL PRIVILEGES ON rpstir.* TO 'rpstir'@'%' IDENTIFIED BY 'Rpstir-123';
flush privileges;

CREATE DATABASE rpstir_test;
GRANT ALL PRIVILEGES ON rpstir_test.* TO 'rpstir'@'localhost' IDENTIFIED BY 'Rpstir-123';
GRANT ALL PRIVILEGES ON rpstir_test.* TO 'rpstir'@'%' IDENTIFIED BY 'Rpstir-123';
flush privileges;

SELECT USER,HOST FROM mysql.user;



use rpstir;

CREATE TABLE `rpki_link_rpvc` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `protocol` varchar(64) NOT NULL COMMENT 'http��https',
  `address` varchar(64) NOT NULL COMMENT 'IP��ַ��������ַ',
  `port`    int(10) unsigned NOT NULL COMMENT '��ַ�˿�',
  `style`   varchar(64) NOT NULL COMMENT '����: vc/rp',
  `create_time` datetime NOT NULL COMMENT '����ʱ��',
  `state` varchar(16) NOT NULL DEFAULT 'valid'  COMMENT 'validΪ��Ч��invalidΪ��Ч',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8 COLLATE=utf8_bin comment='���������ñ��п�����vc���п�����rp';


CREATE TABLE `rpki_link_rpvc_log` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `link_id` int(10) unsigned NOT NULL  COMMENT '��Ӧ��rpki_linked_rpvc_config��id',
  `update_type`   varchar(64) NOT NULL COMMENT '����: all/update,ȫ����������',
  `update_time` datetime NOT NULL COMMENT '����ʱ��',
  `serial_num` int(10)   COMMENT '��������ʱ��serialnum��ȫ��ʱΪ��',
  `result`   varchar(64) COMMENT '���½��: ok/fail',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8 COLLATE=utf8_bin comment='��������־�����¼�¼';



									 
'RP���ݿ� ���VC��ַ									 
insert into rpki_link_rpvc(protocol,address,port,style,create_time,state) 
									 values ('https','202.173.14.103','8444','vc','2019-03-12 1:1:1','valid');

'VC���ݿ⣬���RP��ַ
insert into rpki_link_rpvc(protocol,address,port,style,create_time,state) 
									 values ('https','202.173.14.102','8443','rp','2019-03-12 1:1:1','valid');									 									 
									 
									 
									 
									 


set global read_only=1;
flush privileges;



