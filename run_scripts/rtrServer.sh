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
#  Copyright (C) BBN Technologies 2010.  All Rights Reserved.
# 
#  Contributor(s): Mark Reynolds
# 
#  ***** END LICENSE BLOCK ***** */

# Provide a place to set environment variables and provide arguments
# to allow the server to be invoked as a subsystem
#
# Note that this file should be edited before attempting to run
# First, set the two environment variables correctly
# Then, change the value for the -t flag from 1 to however often the
#   server should check the database for updates (in seconds).
#   A suggested value is 30 (or higher), as it is not critical that
#   updates to the database (which occur at most a few times a day) be
#   propagated to the clients immediately.  (It is set to 1 to make
#   testing go faster.)
# Optionally, change the location of the log file.
#

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../envir.setup

if [ "${RTR_CHECK_INTERVAL}x" = "x" ]; then export RTR_CHECK_INTERVAL=60; fi
$RPKI_ROOT/server/server -l $RPKI_ROOT/server/logs/rtr.log -t $RTR_CHECK_INTERVAL
