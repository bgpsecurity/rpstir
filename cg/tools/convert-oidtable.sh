#!/bin/bash

#
# read a Gardiner-format oidtable and write it out in dumpasn1.cfg format
#

# N.b. requires /bin/bash for "read foo bar" instead of just "read foo"

# set this to wherever encode-oid lives
THIS_SCRIPT_DIR=$(dirname $0)
ENCODE_OID=$THIS_SCRIPT_DIR/encode-oid

if [ ! -x $ENCODE_OID ]; then
    echo set ENCODE_OID in $0 to point to the encode-oid program
    echo currently points to $ENCODE_OID, which doesn\'t exists or is not executable
    exit 1
fi

while read oid desc; do
    eof=$?
    if [ $eof -eq 0 ]; then 
	echo OID = `encode-oid $oid`
	echo Description = $desc \( $oid \) \( from oidtable \)
	echo
    fi
done
