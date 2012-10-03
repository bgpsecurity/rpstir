#!/bin/sh

THIS_SCRIPT_DIR=`dirname "$0"`
. "$THIS_SCRIPT_DIR/../../etc/envir.setup"

exec "$THIS_SCRIPT_DIR/updateTA.py" "$@"
