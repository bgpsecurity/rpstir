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

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $(which $0))
source $THIS_SCRIPT_DIR/../envir.setup

echo About to clear database "${RPKI_DB}" ...
$RPKI_ROOT/proto/rcli -x -y
$RPKI_ROOT/proto/rcli -t $RPKI_ROOT/REPOSITORY -y
