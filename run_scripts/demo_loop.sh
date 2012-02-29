#!/bin/bash

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../envir.setup

cd $RPKI_ROOT

# If loader is not running, start it
if [ -z "$(pgrep -u $USER loader.sh)" ]; then
    run_scripts/loader.sh &
    sleep 1
fi

# Run the garbage collector
run_scripts/garbage.sh

# Run the rsync URI chaser
proto/chaser -f initial_rsync.config

# Update the data for the rtr-server
rtr/rpstir-rtr-update run_scripts/sampleQuerySpecs

# If rtr-server is not running, run it
if [ -z "$(pgrep -u $USER rpstir-rtrd)" ]; then
    rtr/rpstir-rtrd &
fi

echo "ran at `date`" >> /home/demouser/rpki/run_scripts/demo_loop.log
