#!/bin/sh
# run the garbage collector, no required arguments

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../../etc/envir.setup

garbage
