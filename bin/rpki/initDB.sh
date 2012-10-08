#!/bin/sh
# set up an initial database

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../../etc/envir.setup

mkdir -p "`config_get RPKICacheDir`"
mkdir -p "`config_get LogDir`"

echo About to clear database ...
rcli -x -t "`config_get RPKICacheDir`" -y
