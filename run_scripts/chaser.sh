#!/bin/sh
# ***** BEGIN LICENSE BLOCK *****
#  
#  BBN Address and AS Number PKI Database/repository software
#  Verison 1.0
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
#
# run the chaser, one argument is the name of the original config file
#   used for doing the rsync_pull

if [ "${APKI_PORT}x" = "x" ]; then export APKI_PORT=7344; fi
if [ "${APKI_DB}x" = "x" ]; then export APKI_DB=apki; fi
if [ "${APKI_ROOT}x" = "x" ]; then export APKI_ROOT=`pwd | sed 's/\/run_scripts//'`; fi

unset arg
if [ "$2x" = "noexecx" ] || [ "$2X" = "NOEXECX" ]; then arg="-n"; fi

$APKI_ROOT/proto/chaser -f $1 $arg
