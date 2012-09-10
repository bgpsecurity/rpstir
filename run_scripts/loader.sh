#!/bin/sh
# listen for feeder connections and load the data fed into the database

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../envir.setup

exec $RPKI_ROOT/proto/rcli -w $RPKI_PORT -p
