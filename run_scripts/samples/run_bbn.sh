#!/bin/bash

cd $RPKI_ROOT

# Clear file cache and database
rm -rf REPOSITORY LOGS chaser.log rcli.log rsync_aur.log query.log
mkdir -p REPOSITORY
mkdir -p LOGS
run_scripts/initDB.sh

# Start validator component in separate window
xterm -e run_scripts/loader.sh &
sleep 1

# Out-of-band initialization of trust anchor
run_scripts/updateTA.py bbn_conformance.tal

# Chase downward from trust anchor(s) using rsync
proto/chaser -f initial_rsync.config
