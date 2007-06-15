#!/bin/sh

i=0
while [ $i -lt 10000 ] ; do
  cp ${APKI_ROOT}/testing/REPOSITORY/roa/mytest.roa.pem REPOSITORY/roa/roa${i}.roa.pem
  i=$((i + 1))
done
