#!/bin/sh
# run the query client to get information out of the database and repository

if [ "${APKI_PORT}x" = "x" ]; then export APKI_PORT=7344; fi
if [ "${APKI_DB}x" = "x" ]; then export APKI_DB=apki; fi
if [ "${APKI_ROOT}x" = "x" ]; then export APKI_ROOT=`pwd | sed 's/\/run_scripts//'`; fi

$APKI_ROOT/proto/query $*
