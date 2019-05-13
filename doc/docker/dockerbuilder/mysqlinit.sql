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


set global read_only=1;
flush privileges;



