#!/bin/sh

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
