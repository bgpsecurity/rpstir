#!/bin/sh
# listen for feeder connections and load the data fed into the database

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../../etc/envir.setup

rcli -w -p
