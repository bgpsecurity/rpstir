#!/bin/sh

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../envir.setup


i=0
while [ $i -lt 10000 ] ; do
  cp ${RPKI_ROOT}/testing/REPOSITORY/roa/mytest.roa.pem REPOSITORY/roa/roa${i}.roa.pem
  i=$((i + 1))
done
