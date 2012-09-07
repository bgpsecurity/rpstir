#!/bin/sh

cd `dirname "$0"`/../..

. etc/envir.setup

. lib/util/shell_utils


formatted_date () {
    date -u +"%Y-%m-%dT%H:%M:%S"
}

SYNC_START_TIME="`formatted_date`"
run_from_TALs.sh etc/sample-ta/*.tal
SYNC_END_TIME="`formatted_date`"


mkdir -p statistics || fatal "could not create statistics directory"
STATS_DIR="statistics/$SYNC_START_TIME~$SYNC_END_TIME"
mkdir "$STATS_DIR" || fatal "could not create $STATS_DIR"


query.sh -t cert -d pathname -d valfrom -d valto -d flags -i \
    > "$STATS_DIR/query.cert" \
    || fatal "could not query certificates"
