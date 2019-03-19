#!/bin/bash
service crond restart
service mysqld restart
cd /root/rpki/rpstir/bin/
./rpki-rtr-daemon &
cd /root/rpki/rpki-transfer/bin/
./startup.sh &
cd /root/rpki
/bin/bash 