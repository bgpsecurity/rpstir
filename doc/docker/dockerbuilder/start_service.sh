#!/bin/bash
service crond restart
service mysqld restart
cd /root/rpki/rpstir/bin/
./rpstir-initialize  -f 
./rpki-rtr-daemon
cd /root/rpki/rpki-transfer/bin/
./startup.sh
/bin/bash 