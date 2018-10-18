dayt="$(date +%Y%m%d)"
startt="$(date +%Y%m%d-%H:%M:%S)"
echo $startt >> /usr/local/var/log/rpstir/crontab.log.$dayt
rpstir-synchronize >>  /usr/local/var/log/rpstir/crontab.log.$dayt 2>&1 
rpstir-rpki-rtr-update >>  /usr/local/var/log/rpstir/crontab.log.$dayt 2>&1 
endt="$(date +%Y%m%d-%H:%M:%S)"
echo $endt >>  /usr/local/var/log/rpstir/crontab.log.$dayt
