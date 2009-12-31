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
# This script is a shortcut to invoke the script rsync_pull.sh
# It executes rsync to pull down data and then optionally loads it
#   into the database.
# It takes a single argument, which is the name of the configuration
#   file that contains the instructions for what to do.
# 
# The file rsync_mock.config is a sample configuration file.
# The following is the set of variables to define in the configuration file.
#
# DIRS=
#   A list of the form system/dir or "system1/dir1 system2/dir2 ..." (e.g.
#   "apnic.mirin.apnic.net/mock/AFRINIC apnic.mirin.apnic.net/mock/APNIC")
# REPOSITORY=
#   The full path of where the repositories should be deposited
#   (e.g. /home/mudge/rsync_aur/REPOSITORY ) - note: leave the trailing
#   slash off as rsync interprets that to mean something else.
# LOGS=
#   The full path of where the rsync log file (that the AUR program
#   will ultimately use) should be put. 
# DOPULL=
#   NO or no if do not want to pull the data from remote repositories
# DOLOAD=
#   NO or no if do not want to load the data into the database
#
# Addtional documentation is in the rsync_pull.sh file.

# check that we have a config file specified as the arg
if [ $# -ne 1 ] ; then
  echo "usage: $0 config_file"
  echo " look in the source of this script for config format"
  echo " or look at rsync_mock.config as a sample config file"
  exit 1
fi

# set environment variables if not set
if [ "${RPKI_PORT}x" = "x" ]; then export RPKI_PORT=7344; fi
if [ "${RPKI_DB}x" = "x" ]; then export RPKI_DB=rpki; fi
if [ "${RPKI_ROOT}x" = "x" ]; then export RPKI_ROOT=`pwd | sed 's/\/run_scripts//'`; fi

${RPKI_ROOT}/rsync_aur/rsync_pull.sh $1
