#!/bin/bash

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

#================================================================================
# D E S C R I P T I O N :
#
# This file is a script to run a generic test.  Each test is specified as a series
# of files using input parameters to this script.  The generic test consists of a
# set of files to load into a blank repository, a set of actions to execute (these
# are expected to vary widely), a test query to run and expected results to match.
#
# Each test thus consists of the following files:
#  t$1_actions  (actions to execute on the repository)
#  t$2_flist    (files to initially put in repository, may be modified by actions)
#  t$3_query    (query to run to get test results)
#  t$4_expect   (expected results from query)
#
# This script can be run using either two input parameters or multiple input
# parameters.  When only two paraemters are specified all test file names are derived
# from the second parameter and are thus the same (e.g., runt.sh C.cer t1-1 results
# in files named t1-1_actions, t1-1_flist, t1-1_query and t1-1_expect).
#
# If multiple parameters are given then each is used in turn to generate the actions,
# flist, query and expect file names.  Note that the first parameter is reused for
# any unspecified parameters in this case.  The intention here is to allow reuse of
# test source files (especially the flist, query and expect files).
#
# Thus for example, to run "test case C.cer 1-12", the following are equivalent
# "runt.sh C.cer 1-12 1-1 1-1 1-1" and "runt.sh C.cer 1-12 1-1"
#
# This assumes that the final result should be the same between tests 1-1 and 1-12,
# if not, something along the lines of: "runt.sh C.cer 1-12 1-1 1-1 1-12" would be needed.
#
# If all of the input files for a given test are specific to that test then the
# test is run using two parmeters, for example "runt.sh C.cer 3-20".  
#
# If the actual results do NOT match the expected results, the script creates a file
# named t$1_error with the differences.  The absence of any file named *_error means
# that all tests pass.  Note the any pre-existing x_error file is renamed to
# x_error.sav.N (where N is 1, 2, etc.) at the start of each test.
#
#================================================================================



#================================================================================
# G L O B A L S :
#
auth="Jon Shapiro"
edit="14"
date="20-Aug-08"

act_fname=
flist_fname=
query_fname=
expect_fname=
got_fname=
error_fname=
tancor_fname=
test_name=
scriptStartedListener=0
rDir=


#================================================================================
# F U N C T I O N S :
#

#--------------------------------------------------------------------------------
# print usage statement to stdout
#
printUsage() {

  echo "usage: $0 test-to-run trust_anchor_filename [opt: flist] [opt: query] [opt: expected]"
  echo ""
  echo "example, to run test '1-1', use: $0 Foo.cer 1-1 (the 't' is automatically supplied)"
  echo "         this specifies to use Foo.cer as the trust anchor, and to run"
  echo "         the set of actions in t1-1_actions file (actions to execute on database)"
  echo "         and t1-1_flist (the list of cer, crl, roa, man files to initially load),"
  echo "         and t1-1_query (the query command to run),"
  echo "         and t1-1_expect (the expected result from the query)"
  echo ""
  echo "example-2, to run test 1-2 using some 1-1 info, use: $0 Foo.cer 1-2 1-1 1-1 1-2"
  echo "         this has different actions and results, but the same starting files and query"
  echo ""
}


#--------------------------------------------------------------------------------
# validate environment program is being run in, return negative value for error
# and 0 if everything checks out
#
checkEnvironment() {

  goodToGo=1
  
  if [ -z $RPKI_DB ]; then
    echo " *** no database specified in shell as RPKI_DB, can't run" | tee -a $error_fname
    goodToGo=0
  fi
      
  if [ -z $RPKI_ROOT ]; then
    echo " *** no directory root specified in shell as RPKI_ROOT, can't run" | tee -a $error_fname
    goodToGo=0
  fi
  
  if [ -z $RPKI_PORT ]; then
    echo " *** no database port specified in shell as RPKI_PORT, can't run" | tee -a $error_fname
    goodToGo=0
  fi

  # if environment set up, check for 'listener' (rcli listening on a port)
  # if not found, try to create in the background, if this fails, return error
  #
  if [ $goodToGo -eq 1 ]; then
    listenStr=`ps -ef|grep $USER|grep "rcli -w"|grep -v "grep"`
    if [ -z "$listenStr" ]; then
      $RPKI_ROOT/proto/rcli -w $RPKI_PORT -p &
      sleep 4
      
      listenStr=`ps -ef|grep $USER|grep "rcli -w"|grep -v "grep"`
      if [ -z "$listenStr" ]; then
        echo " *** could not find or start listener shell (rcli -w \$RPKI_PORT -p), can't run" | tee -a $error_fname
        goodToGo=0
      else
        echo " *** script started listener"
        scriptStartedListener=1
      fi
    fi
  fi

  if [ $goodToGo -ne 1 ]; then
    return -1
  fi
  
  return 0
}


#--------------------------------------------------------------------------------
# validate input parameters, setup global variables for running, if any error
# occurs return a negative value, otherwise return 0
#
checkInputAndSetupGlobals() {

  if [ $# -lt 2 ]; then
    printUsage
    return -1
  fi

  tanchor_fname=$1

  test_name=$2
      
  act_fname=t$2_actions
  flist_fname=t$2_flist
  query_fname=t$2_query
  expect_fname=t$2_expect
  got_fname=t$2_got
  error_fname=t$2_error

  if [ $# -ge 3 ]; then
    flist_fname=t$3_flist
  fi

  if [ $# -ge 4 ]; then
    query_fname=t$4_query
  fi

  if [ $# -ge 5 ]; then
    expect_fname=t$5_expect
  fi

  # rename (to save) got file if it exists
  #
  if [ -f $got_fname ]; then
      i=1
      while [ -f $got_fname.sav.$i ]
        do
        i=`expr $i + 1`
      done
      mv $got_fname $got_fname.sav.$i
      echo " *** Existing got file saved as" $got_fname.sav.$i
  fi

  # rename (to save) error file if it exists
  #
  if [ -f $error_fname ]; then
      i=1
      while [ -f $error_fname.sav.$i ]
        do
        i=`expr $i + 1`
      done
      mv $error_fname $error_fname.sav.$i
      echo " *** Existing error file saved as" $error_fname.sav.$i
  fi

  # debug block ... remove later
  # echo "tanchor_fname is:" $tanchor_fname
  # echo "act_fname is:"     $act_fname
  # echo "flist_fname is:"   $flist_fname
  # echo "query_fname is:"   $query_fname
  # echo "expect_fname is:"  $expect_fname
  # echo "got_fname is:"     $got_fname
  # echo "error_fname is:"   $error_fname

  # ensure all required files exist, write out error and exit if not
  # note: 'got' file is not required as it is an output
  #
  goodToGo=1
  
  if [ ! -f $tanchor_fname ]; then
      echo " *** Error, no trust anchor file" $tanchor_fname "found" | tee -a $error_fname
      goodToGo=0
  fi
  
  if [ ! -f $act_fname ]; then
      echo " *** Error, no actions file" $act_fname "found" | tee -a $error_fname
      goodToGo=0
  fi

  if [ ! -f $flist_fname ]; then
      echo " *** Error, no flist file" $flist_fname "found" | tee -a $error_fname
      goodToGo=0
  fi

  if [ ! -f $query_fname ]; then
    echo " *** Error, no query file" $query_fname "found" | tee -a $error_fname
    goodToGo=0
  fi

  if [ ! -f $expect_fname ]; then
    echo " *** Error, no expect results file" $expect_fname "found" | tee -a $error_fname
    goodToGo=0
  fi

  if [ $goodToGo -ne 1 ]; then
    echo " *** Error, program exiting without running test" $1 | tee -a $error_fname
    return -2
  fi

  return 0
}


#--------------------------------------------------------------------------------
# empty the database if it exists, create it if it does not
#
createEmptyDatabase() {

  # here set the global variable that specifies the repository directory (rDir)
  #
  rDir=$RPKI_ROOT/testcases

  # note: for the below to work, the rcli executable must be compiled without
  #       using "getpass()", which is obsolete and which reads directly from
  #       /dev/tty ... a local version "debug_getpass()" has been supplied in
  #       the file for at least temporary use
  # note-2: for some reason the stdin redirection does not work from within
  #         the bash.sh script ... so the debug_getpass is now really a
  #         dummy call that supplies the password.  Fixing TBD.  1-Aug-08 js
  #
  $RPKI_ROOT/proto/rcli -x -y <<EOI
password
EOI
  $RPKI_ROOT/proto/rcli -t $rDir -y <<EOI
password
EOI

  return 0
}


#--------------------------------------------------------------------------------
# initialize the database by loading each file named in the flist_fname file
#
initializeDatabase() {

  # note: the trunst anchor must be delivered by 'out of band' means,
  #       i.e., it can not be delivered via the listener port -> rcli,
  #       (it fails silently), but instead has to be directly loaded thusly:
  #
  $RPKI_ROOT/proto/rcli -y -F $tanchor_fname
  
  echo "$RPKI_ROOT/rsync_aur/rsync_aur -s -t $RPKI_PORT -f $RPKI_ROOT/testcases/$flist_fname -d $rDir"
  $RPKI_ROOT/rsync_aur/rsync_aur -s -t $RPKI_PORT -f $RPKI_ROOT/testcases/$flist_fname -d $rDir
  return
}


#--------------------------------------------------------------------------------
# execute actions on the database by running the specified test script
#
modifyDatabase() {

  echo " *** running actions "
  . $act_fname
  return
}


#--------------------------------------------------------------------------------
# execute query command to examine state of database
#
runQuery() {

  echo " *** running query "
  . $query_fname > $got_fname
  return
}


#--------------------------------------------------------------------------------
# compare actual with expected results, log error if they differ (write to
# error_fname which should be empty at this point, and copy the actual results
# to the error file), otherwise delete the actual results file (got_fname)
# which should be empty
#
compareResults() {

  echo " *** checking results"
  diff -b -w $got_fname $expect_fname > $0.diff.tmp
  diffLen=`wc -l $0.diff.tmp | cut -d" " -f1`
  if [ "$diffLen" -ne 0 ]; then
    dateStr=`date`
    echo " *** test run on " $dateStr "did not get expected results (see file $expect_fname)" | tee -a $error_fname
    echo " *** got the following in response to query in file $query_fname" >> $error_fname
    echo "" >> $error_fname
    cat $got_fname >> $error_fname
  else
    echo " *** test" $test_name "passed, no difference in actual vs. expected results"
    rm $got_fname
  fi
  rm $0.diff.tmp  

  return
}


#--------------------------------------------------------------------------------
# kill the rcli port listener process (started by this script) ... otherwise
# it remains as a detached process and the user may forget to kill it!
#
killListener() {

  if [ $scriptStartedListener -eq 1 ]; then
    listenPID=`ps -ef|grep $USER|grep "rcli -w"|grep -v "grep"|gawk '{print $2};'`
    echo " *** killing listener process started by $0, PID" $listenPID
    kill -9 $listenPID
  fi
  
  return
}


#================================================================================
# M A I N :
#

keepGoing=1

checkInputAndSetupGlobals $*
retval=$?
if [ $retval -ne 0 ]; then
  echo " *** Error, input parameters invalid, aborting" | tee -a $error_fname
  keepGoing=0
fi

if [ $keepGoing -eq 1 ]; then
  checkEnvironment
  retval=$?
  if [ $retval -ne 0 ]; then
    echo " *** Error, environment variables not set, aborting" | tee -a $error_fname
    keepGoing=0
  fi
fi

if [ $keepGoing -eq 1 ]; then
  dateStr=`date +%m-%d-%Y`
  echo " *** running test" $test_name "on (mdy)" $dateStr

  createEmptyDatabase
  retval=$?
  if [ $retval -ne 0 ]; then
    echo " *** Error, create database failed, aborting" | tee -a $error_fname
    keepGoing=0
  fi
fi

if [ $keepGoing -eq 1 ]; then
  initializeDatabase
  retval=$?
  if [ $retval -ne 0 ]; then
    echo " *** Error, initialize database failed, aborting" | tee -a $error_fname
    keepGoing=0
  fi
fi

if [ $keepGoing -eq 1 ]; then
  modifyDatabase
  retval=$?
  if [ $retval -ne 0 ]; then
    echo " *** Error, modify database (actions) failed, aborting" | tee -a $error_fname
    keepGoing=0
  fi
fi

if [ $keepGoing -eq 1 ]; then

  # note: since some queries result in empty files, can not test the result of the query
  #       command via retval=$?, as this aborts test when an empty file is the result!
  #       ... so just runQuery and compareResults
  #
  runQuery
  compareResults
  retval=$?
  if [ $retval -ne 0 ]; then
    echo " *** Error, compare results failure, aborting" | tee -a $error_fname
    keepGoing=0
  fi
fi

killListener

exit
