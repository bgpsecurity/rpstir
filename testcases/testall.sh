#!/bin/sh


# try adding everything to the db

BASE=`cd ..; pwd`

echo initializing database
../testing/initDB

echo adding root certificate
$BASE/proto/rcli -y -F C.cer

# files=`ls C?*.cer R*.roa M*.man L*.crl | grep -v 'C.*M..cer' | grep -v 'C.*R..cer' | grep -v 'C.*X.cer'`

files=`ls C[0-9].cer C[0-9][0-9].cer C[0-9][0-9][0-9].cer R*.roa M*.man L*.crl`

echo adding $files
for i in $files; do
    printf "%15s: " `basename $i`
    $BASE/proto/rcli -y -f $i
done
