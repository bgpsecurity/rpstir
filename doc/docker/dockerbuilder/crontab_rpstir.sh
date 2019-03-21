#!/bin/bash

# chmod +x crontab_rpstir.sh
# set crontab -e
# 0 */4  * * *  /root/rpstir/rpstir/doc/docker/dockerbuilder/crontab_rpstir.sh


export /root/.bash_profile  
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SHELL=/bin/bash

dayt="$(date +%Y%m%d)"
startt="$(date +%Y%m%d-%H:%M:%S)"
echo $startt >> /usr/local/var/log/rpstir/crontab.log.$dayt
/usr/local/bin/rpstir-synchronize >>  /usr/local/var/log/rpstir/crontab.log.$dayt 2>&1 
/usr/local/bin/rpstir-rpki-rtr-update >>  /usr/local/var/log/rpstir/crontab.log.$dayt 2>&1 
#curl -X POST --insecure  "https://127.0.0.1:8443/rp/1.0/pushrtrincr"
/root/rpki/rpki-transfer/bin/pushrtrincr.sh
endt="$(date +%Y%m%d-%H:%M:%S)"
echo $endt >>  /usr/local/var/log/rpstir/crontab.log.$dayt
