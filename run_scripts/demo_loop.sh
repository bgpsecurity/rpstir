#!/bin/bash

cd $RPKI_ROOT

# If loader is not running, start it
if [ -z "$(pgrep -u demo loader.sh)" ]; then
    xterm -e run_scripts/loader.sh &
    sleep 1
fi

# Run the garbage collector
run_scripts/garbage.sh

# Run the rsync URI chaser
proto/chaser -f initial_rsync.config

# Update the data for the rtr-server
run_scripts/rtrUpdate.sh

# If rtr-server is not running, run it
if [ -z "$(pgrep -u demo rpstir-rtrd.sh)" ]; then
    run_scripts/rtrServer.sh &
fi
