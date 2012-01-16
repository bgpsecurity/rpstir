#!/bin/sh
# set up an initial database

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../envir.setup

mkdir -p $RPKI_ROOT/REPOSITORY
mkdir -p $RPKI_ROOT/LOGS

echo About to clear database "${RPKI_DB}" ...
$RPKI_ROOT/proto/rcli -x -t $RPKI_ROOT/REPOSITORY -y
