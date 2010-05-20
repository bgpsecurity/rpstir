#!/bin/sh

# ***** BEGIN LICENSE BLOCK *****
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
#  Copyright (C) BBN Technologies 2010.  All Rights Reserved.
# 
#  Contributor(s): Mark Reynolds
# 
#  ***** END LICENSE BLOCK ***** */

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../envir.setup

echo "delete from apki_cert;" | $RPKI_MYSQL_CMD
echo "delete from apki_roa;" | $RPKI_MYSQL_CMD
echo "delete from apki_crl;" | $RPKI_MYSQL_CMD
echo "delete from apki_dir;" | $RPKI_MYSQL_CMD
echo "update apki_metadata set rootdir=\"${RPKI_ROOT}/performance/REPOSITORY\";" | $RPKI_MYSQL_CMD
echo "Running performance test, output in perf_output"
${RPKI_ROOT}/run_scripts/rsync_pull.sh rsync_perf.config > perf_output
