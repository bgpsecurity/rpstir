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
# run the doUpdate application for the RTR server
#   requires an argument that is the staleness specs file

if [ "${RPKI_DB}x" = "x" ]; then export RPKI_DB=rpki; fi
if [ "${RPKI_ROOT}x" = "x" ]; then export RPKI_ROOT=`pwd | sed 's/\/run_scripts//'`; fi

$RPKI_ROOT/server/doUpdate $*

