#!/bin/sh

cd `dirname "$0"`/../..

. etc/envir.setup

. lib/util/shell_utils


formatted_date () {
    date -u +"%Y-%m-%dT%H:%M:%S"
}

SYNC_START_TIME="`formatted_date`"
run_from_TALs.sh etc/sample-ta/*.tal \
    || fatal "error syncing with repositories"
SYNC_END_TIME="`formatted_date`"


mkdir -p statistics || fatal "could not create statistics directory"
STATS_DIR="statistics/$SYNC_START_TIME~$SYNC_END_TIME"
mkdir "$STATS_DIR" || fatal "could not create $STATS_DIR"


cp -R LOGS chaser.log rcli.log rsync_aur.log rsync_listener.log "$STATS_DIR" \
    || fatal "could not copy LOGS"

ls -lR REPOSITORY \
    > "$STATS_DIR/REPOSITORY.list" \
    || fatal "could not list REPOSITORY"


query.sh -t cert -d pathname -d valfrom -d valto -d flags -i \
    > "$STATS_DIR/query.cer" \
    || fatal "could not query certificates"

query.sh -t crl -d pathname -d last_upd -d next_upd -d flags -i \
    > "$STATS_DIR/query.crl" \
    || fatal "could not query CRLs"

query.sh -t roa -d pathname -d flags -i \
    > "$STATS_DIR/query.roa" \
    || fatal "could not query ROAs"

query.sh -t manifest -d pathname -d this_upd -d next_upd -d flags -i \
    > "$STATS_DIR/query.mft" \
    || fatal "could not query manifests"
