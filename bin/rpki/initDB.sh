#!/bin/sh
# set up an initial database

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../../etc/envir.setup

mkdir -p "`config_get RootDir`/REPOSITORY"
mkdir -p "`config_get RootDir`/LOGS"

echo About to clear database ...
rcli -x -t "`config_get RootDir`/REPOSITORY" -y
