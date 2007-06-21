#!/bin/sh

echo "delete from apki_cert;" | mysql $APKI_DB -u mysql
echo "delete from apki_roa;" | mysql $APKI_DB -u mysql
echo "delete from apki_crl;" | mysql $APKI_DB -u mysql
echo "delete from apki_dir;" | mysql $APKI_DB -u mysql
echo "update apki_metadata set rootdir=\"${APKI_ROOT}/performance/REPOSITORY\";" | mysql $APKI_DB -u mysql
echo "Running performance test, output in perf_output"
${APKI_ROOT}/run_scripts/rsync_pull.sh rsync_perf.config > perf_output
