#!/bin/sh
set -e

# try adding everything to the db

BASE=`cd ..; pwd`
REPO=$BASE/testing/REPOSITORY/test

echo copying objects to $REPO
rm -f $REPO/*
cp C?*.cer R*.roa M*.man L*.crl $REPO

echo initializing database
../testing/initDB

echo adding root certificate
$BASE/proto/rcli -y -F C.cer

echo adding objects
for i in `ls $REPO/* | grep -v X`; do
    echo -n `basename $i`:
    $BASE/proto/rcli -f $i
done
