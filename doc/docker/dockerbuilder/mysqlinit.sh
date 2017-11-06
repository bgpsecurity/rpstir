#!/bin/sh

cd /root/mysql

if [ ! -d "/var/lib/mysql" ]; then
  mysqld  --initialize-insecure  --user=mysql --console
fi


mysql -uroot < mysqlinit.sql


