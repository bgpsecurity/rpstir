#!/bin/sh
# run the query client to get information out of the database and repository

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../envir.setup

$RPKI_ROOT/proto/query $*
