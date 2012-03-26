#!/bin/bash -e

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../envir.setup

cd $RPKI_ROOT

# If loader is not running, start it
if [ -z "$(pgrep -u $USER loader.sh)" ]; then
    ./run_scripts/loader.sh &
    sleep 1
fi
echo "`date`  after loader, pwd=$PWD" >>~/l.log

# Run the rsync URI chaser
./run_scripts/chaser.sh
echo "`date`  after chaser, pwd=$PWD" >>~/l.log

# Run the garbage collector
./run_scripts/garbage.sh
echo "`date`  after garbage, pwd=$PWD" >>~/l.log

# Update the data for the rtr-server
./rtr/rpstir-rtr-update run_scripts/sampleQuerySpecs
echo "`date`  after update, pwd=$PWD" >>~/l.log

# If rtr-server is not running, run it
if [ -z "$(pgrep -u $USER rpstir-rtrd)" ]; then
    ./rtr/rpstir-rtrd &
fi
echo "`date`  after rtr, pwd=$PWD" >>~/l.log

echo "---------- ran at `date` ----------"
