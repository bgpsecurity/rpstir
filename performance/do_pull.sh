#!/bin/sh

echo "delete from apki_cert;" | mysql $RPKI_DB -u mysql
echo "delete from apki_roa;" | mysql $RPKI_DB -u mysql
echo "delete from apki_crl;" | mysql $RPKI_DB -u mysql
echo "delete from apki_dir;" | mysql $RPKI_DB -u mysql
echo "update apki_metadata set rootdir=\"${RPKI_ROOT}/performance/REPOSITORY\";" | mysql $RPKI_DB -u mysql
echo "Running performance test, output in perf_output"
${RPKI_ROOT}/run_scripts/rsync_pull.sh rsync_perf.config > perf_output
