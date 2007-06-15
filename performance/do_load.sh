#!/bin/sh

${APKI_ROOT}/rsync_aur/rsync_aur -t ${APKI_PORT} -d ${APKI_ROOT}/performance/REPOSITORY/apnic.mirin.apnic.net/mock -f ${APKI_ROOT}/performance/LOGS/apnic.mirin.apnic.net/mock.log
