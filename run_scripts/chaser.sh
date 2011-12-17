#!/bin/sh
#
# run the chaser, one argument is the name of the original config file
#   used for doing the rsync_pull

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../envir.setup

unset arg
if [ "$2x" = "noexecx" ] || [ "$2X" = "NOEXECX" ]; then arg="-n"; fi

$RPKI_ROOT/proto/chaser -f $1 $arg
