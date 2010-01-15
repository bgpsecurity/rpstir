#!/bin/sh
#
# Usage: ./runSubsystemTest.sh <testID> <numsteps>
#
# This script runs a subsystem test by clearing the database, starting
# a loader, and then successively running the scripts ./stepN.M where
# N=<testID> and M ranges from 1..<numsteps>.  It exits with return
# code 0 if successful, nonzero otherwise.

if [ "$#" -ne "2" ]; then
    echo "Usage: $0 <testID> <numsteps>"
    echo
    echo "This script runs a subsystem test by clearing the database, starting"
    echo "a loader, and then successively running the scripts ./stepN.M where"
    echo "N=<testID> and M ranges from 1..<numsteps>.  It exits with return"
    echo "code 0 if successful, nonzero otherwise."
    exit 1
fi

TESTID=$1
NUM_STEPS=$2

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $(which $0))
source $THIS_SCRIPT_DIR/../envir.setup

# test functions
source $THIS_SCRIPT_DIR/test.include

cd $THIS_SCRIPT_DIR

# clear database
./initDB
check_errs $? "initDB failed!"

# check for existing loader and fail if so
nc -z localhost $RPKI_PORT
if [ $? -eq "0" ]; then
    echo "ERROR: port $RPKI_PORT is already in use.  Aborting subsystem test."
    exit 3
fi

# start loader
../proto/rcli -w $RPKI_PORT -p &
LOADER_PID=$!
sleep 1
echo "Loader started (pid = $LOADER_PID)..."

# run all steps
NUM_PASSED=0
NUM_TOTAL=$NUM_STEPS

N=1
while [ $N -le $NUM_TOTAL ]; do
    ./step${TESTID}.${N}
    if [ "$?" -eq "0" ]; then
	let "NUM_PASSED += 1"
    fi
    let "N += 1"
done

# cleanup
kill -9 $LOADER_PID
sleep 1

# display results
if [ "$NUM_PASSED" -eq "$NUM_TOTAL" ]; then
    TEST_STATUS="PASS"
else
    TEST_STATUS="FAIL"
fi
echo "-------------------------------------------------------------------"
echo "Subsystem Test $TESTID: $NUM_PASSED out of $NUM_TOTAL steps passed."
echo "Subsystem Test $TESTID: $TEST_STATUS"
echo "-------------------------------------------------------------------"

# exit with nonzero if test failed
if [ "$TEST_STATUS" != "PASS" ]; then
    exit 2
fi
