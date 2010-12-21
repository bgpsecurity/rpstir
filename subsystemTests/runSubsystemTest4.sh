#!/bin/sh
#
#  ***** BEGIN LICENSE BLOCK *****
# 
#  BBN Address and AS Number PKI Database/repository software
#  Version 3.0-beta
# 
#  US government users are permitted unrestricted rights as
#  defined in the FAR.
# 
#  This software is distributed on an "AS IS" basis, WITHOUT
#  WARRANTY OF ANY KIND, either express or implied.
# 
#  Copyright (C) Raytheon BBN Technologies Corp. 2010.  All Rights Reserved.
# 
#  Contributor(s): Mark Reynolds
# 
#  ***** END LICENSE BLOCK ***** */

# Usage: ./runSubsystemTest.sh <testID> <numsteps>
#
# This script runs a subsystem test by clearing the database, starting
# a loader, and then successively running the scripts ./stepN.M where
# N=<testID> and M ranges from 1..<numsteps>.  It exits with return
# code 0 if successful, nonzero otherwise.

if [ "$#" -ne "0" ]; then
    echo "Usage: $0 <testID> <numsteps>"
    echo
    echo "This script runs a subsystem test by clearing the database, starting"
    echo "a loader, and then successively running the scripts ./stepN.M where"
    echo "N=<testID> and M ranges from 1..<numsteps>.  It exits with return"
    echo "code 0 if successful, nonzero otherwise."
    exit 1
fi

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../envir.setup

# test functions
. $THIS_SCRIPT_DIR/test.include

cd $THIS_SCRIPT_DIR

# refresh test certs
  cd testcases4_LTA
  for f in C?*.raw 
  do
    filename=`basename $f .raw`
    $RPKI_ROOT/cg/tools/rr <$f > ${filename}.cer
  done
  $RPKI_ROOT/cg/tools/update_cert 0D 2Y C?*.cer 
  cd ../

# check for existing loader and fail if so
nc -z localhost $RPKI_PORT
if [ $? -eq "0" ]; then
    echo "ERROR: port $RPKI_PORT is already in use.  Aborting subsystem test."
    exit 3
fi

NUM_PASSED=0 
N=1
while [ $N -le "4" ]; do
# clear database
    ./initDB4
    check_errs $? "initDB failed!"
    ../proto/rcli -w $RPKI_PORT -c testcases4_LTA/LTA/case${N} &
    LOADER_PID=$!
     echo "Loader started for case ${N}"
     sleep 1
     ./step4
     cd testcases4_LTA/LTA 
     $RPKI_ROOT/cg/tools/checkLTAtest case${N} C*.cer
     cd ../../
    if [ "$?" -eq "0" ]; then
	NUM_PASSED=$(( $NUM_PASSED + 1 ))
    fi
    N=$(( $N + 1 ))
done

 
# display results
if [ "$NUM_PASSED" -eq "4" ]; then
    TEST_STATUS="PASS"
else
    TEST_STATUS="FAIL"
fi
echo "-------------------------------------------------------------------"
echo "Subsystem Test $TESTID: $NUM_PASSED out of 4 steps passed."
echo "Subsystem Test $TESTID: $TEST_STATUS"
echo "-------------------------------------------------------------------"

# exit with nonzero if test failed
if [ "$TEST_STATUS" != "PASS" ]; then
    exit 2
fi
