#!/bin/sh

# ***** BEGIN LICENSE BLOCK *****
#
# BBN Address and AS Number PKI Database/repository software
# Version 3.0-beta
#
# US government users are permitted unrestricted rights as
# defined in the FAR.
#
# This software is distributed on an "AS IS" basis, WITHOUT
# WARRANTY OF ANY KIND, either express or implied.
#
# Copyright (C) BBN Technologies 2010.  All Rights Reserved.
#
# Contributor(s): Chris Small
#
# ***** END LICENSE BLOCK ***** */

# run test_casn_random with $max different files of random bits each
# file is of size $filesize. If the test core dumps or generates
# output other than what we expect, save the input test file so we can
# run again with a debugger attached to see what's happening

# clean up on exit
trap abort 1 2 15
abort() 
{
    echo aborting
    rm -f $out $tmp
    exit 1
}
    
# how many times to try
max=1000000

# our temporary output file
out=$$.tmp

# ignore this output (egrep format). anything else is suspect
ignore="Error #1:|Error #22:"

# how big to make files (in bytes)
filesize=16384

# how often to offer feedback (each $feedback iterations)
feedback=100

# loop
i=0
while [ $i -lt $max ]; do

    # create a random file
    tmp=$i.test
    dd if=/dev/random of=$tmp bs=$filesize count=1 2>/dev/null

    # run the test
    ./test_casn_random $tmp >$out 2>&1 

    # did it fail?
    if [ $? != 0 ]; then
	echo test aborted, saving $tmp and $i.out
	cp $out $i.out
    else
	# check for lines in the output that aren't in the ignore list
	egrep -v "$ignore" $out
	if [ $? != 1 ]; then
	    echo suspicious output, keeping file $tmp and $i.out
	    cp $out $i.out
	else
	    # everything looks good, delete it and go on
	    rm $tmp
	fi
    fi
    
    # next
    i=`expr $i + 1`

    # user feedback
    if [ `expr $i % $feedback` -eq 0 ]; then
	echo iter $i done
    fi
done
