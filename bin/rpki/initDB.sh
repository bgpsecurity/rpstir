#!/bin/sh
# set up an initial database

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../../etc/envir.setup

mkdir -p "$CONFIG_ROOT_DIR/REPOSITORY"
mkdir -p "$CONFIG_ROOT_DIR/LOGS"

echo About to clear database ...
rcli -x -t "$CONFIG_ROOT_DIR/REPOSITORY" -y
