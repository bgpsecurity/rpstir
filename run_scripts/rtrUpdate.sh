#!/bin/sh
# run the doUpdate application for the RTR server
#   requires an argument that is the staleness specs file

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../envir.setup


$RPKI_ROOT/server/doUpdate $*
