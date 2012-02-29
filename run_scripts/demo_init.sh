#!/bin/bash

cd $RPKI_ROOT

# Clear file cache and database
rm -rf REPOSITORY LOGS chaser.log rcli.log rsync_aur.log query.log
mkdir -p REPOSITORY
mkdir -p LOGS
run_scripts/initDB.sh

# Start validator component in separate window
run_scripts/loader.sh &
sleep 1

# Out-of-band initialization of trust anchor
#run_scripts/updateTA.py trust-anchor/afrinic.tal
run_scripts/updateTA.py trust-anchor/apnic.tal
#run_scripts/updateTA.py trust-anchor/arin.tal
run_scripts/updateTA.py trust-anchor/lacnic.tal
run_scripts/updateTA.py trust-anchor/ripe-ncc-root.tal

# Chase downward from trust anchor(s) using rsync
proto/chaser -f initial_rsync.config
