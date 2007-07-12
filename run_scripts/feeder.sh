#!/bin/sh
# only run this script if an rsync_pull has been run, but some log files
#   were not fed into the loader
#   (possible reasons the log files were not loaded: the loader was not
#    running, the DOLOAD variable was not set)
# it takes one argument: the full pathname of the logfile
# multiple log files should be fed one at a time

if [ "${APKI_PORT}x" = "x" ]; then export APKI_PORT=7344; fi
if [ "${APKI_DB}x" = "x" ]; then export APKI_DB=apki; fi
if [ "${APKI_ROOT}x" = "x" ]; then export APKI_ROOT=`pwd | sed 's/\/run_scripts//'`; fi

$APKI_ROOT/rsync_aur/rsync_aur -s -t $APKI_PORT -f $1 -d $APKI_ROOT/REPOSITORY

