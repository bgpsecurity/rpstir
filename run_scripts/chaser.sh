#!/bin/sh
# run the chaser, one argument is the name of the original config file
#   used for doing the rsync_pull

if [ "${APKI_PORT}x" = "x" ]; then APKI_PORT=7344; fi
if [ "${APKI_DB}x" = "x" ]; then APKI_DB=apki; fi
if [ "${APKI_ROOT}x" = "x" ]; then APKI_ROOT=`pwd | sed 's/\/run_scripts//'`; fi

$APKI_ROOT/proto/chaser $1
