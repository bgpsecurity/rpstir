#!/bin/bash

export /root/.bash_profile  
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SHELL=/bin/bash

dayt="$(date +%Y%m%d)"
startt="$(date +%Y%m%d-%H:%M:%S)"
echo $startt >> /usr/local/var/log/rpstir/crontab.log.$dayt
/usr/local/bin/rpstir-synchronize >>  /usr/local/var/log/rpstir/crontab.log.$dayt 2>&1 
/usr/local/bin/rpstir-rpki-rtr-update >>  /usr/local/var/log/rpstir/crontab.log.$dayt 2>&1 
endt="$(date +%Y%m%d-%H:%M:%S)"
echo $endt >>  /usr/local/var/log/rpstir/crontab.log.$dayt
