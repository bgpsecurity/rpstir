#!/bin/sh
# set up an initial database

if [ "${APKI_PORT}x" = "x" ]; then export APKI_PORT=7344; fi
if [ "${APKI_DB}x" = "x" ]; then export APKI_DB=apki; fi
if [ "${APKI_ROOT}x" = "x" ]; then export APKI_ROOT=`pwd | sed 's/\/run_scripts//'`; fi

$APKI_ROOT/proto/rcli -x -y
$APKI_ROOT/proto/rcli -t $APKI_ROOT/REPOSITORY -y
