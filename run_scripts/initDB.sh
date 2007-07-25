#!/bin/sh
# ***** BEGIN LICENSE BLOCK *****
#  
#  BBN Address and AS Number PKI Database/repository software
#  Version 1.0
#  
#  US government users are permitted unrestricted rights as
#  defined in the FAR.  
# 
#  This software is distributed on an "AS IS" basis, WITHOUT
#  WARRANTY OF ANY KIND, either express or implied.
# 
#  Copyright (C) BBN Technologies 2007.  All Rights Reserved.
# 
#  Contributor(s):  David Montana
# 
# ***** END LICENSE BLOCK *****
# set up an initial database

if [ "${APKI_PORT}x" = "x" ]; then export APKI_PORT=7344; fi
if [ "${APKI_DB}x" = "x" ]; then export APKI_DB=apki; fi
if [ "${APKI_ROOT}x" = "x" ]; then export APKI_ROOT=`pwd | sed 's/\/run_scripts//'`; fi

$APKI_ROOT/proto/rcli -x -y
$APKI_ROOT/proto/rcli -t $APKI_ROOT/REPOSITORY -y
