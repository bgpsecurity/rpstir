#!/bin/sh

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $(which $0))
source $THIS_SCRIPT_DIR/../envir.setup

${RPKI_ROOT}/rsync_aur/rsync_aur -t ${RPKI_PORT} -d ${RPKI_ROOT}/performance/REPOSITORY/apnic.mirin.apnic.net/mock -f ${RPKI_ROOT}/performance/LOGS/apnic.mirin.apnic.net/mock.log
