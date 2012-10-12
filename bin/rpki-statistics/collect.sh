#!/bin/sh

# cron runs this script once every X time period to collect statistics
# from the global RPKI

cd `dirname "$0"`/../..

. etc/envir.setup > /dev/null

. lib/util/shell_utils


LOCK_FILE="statistics.lock"

cleanup () {
    mutex_unlock "$LOCK_FILE"
}

mutex_trylock "$LOCK_FILE" || exit 1
trap cleanup 0


formatted_date () {
    date -u +"%Y-%m-%dT%H:%M:%S"
}

software_version () {
    git describe --tags --long --always
}

SOFTWARE_VERSION_START="`software_version`"

# Note: etc/sample-ta/*.tal on rtr-test:~dmandelb/statistics/ includes ARIN
SYNC_START_TIME="`formatted_date`"
run_from_TALs.sh etc/sample-ta/*.tal \
    > run.log 2>&1 \
    || fatal "error syncing with repositories"
SYNC_END_TIME="`formatted_date`"


mkdir -p statistics || fatal "could not create statistics directory"
STATS_DIR="statistics/$SYNC_START_TIME~$SYNC_END_TIME"
mkdir "$STATS_DIR" || fatal "could not create $STATS_DIR"


cp -R \
    LOGS \
    REPOSITORY \
    chaser.log \
    rcli.log \
    rsync_aur.log \
    run.log \
    "$STATS_DIR" \
    || fatal "could not copy files"

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

results.py > "$STATS_DIR/results" \
    || fatal "could not run results.py"

results.py -v > "$STATS_DIR/results.verbose" \
    || fatal "could not run results.py (verbose)"

SOFTWARE_VERSION_END="`software_version`"

test "$SOFTWARE_VERSION_START" = "$SOFTWARE_VERSION_END" \
    || fatal "software changed from $SOFTWARE_VERSION_START to $SOFTWARE_VERSION_END during the run"

echo "$SOFTWARE_VERSION_START" > "$STATS_DIR/version"

tar -cpzf "$STATS_DIR.tgz" -C `dirname "$STATS_DIR"` `basename "$STATS_DIR"` \
    || fatal "could not make $STATS_DIR.tgz"

rm -rf "$STATS_DIR" || fatal "could not remove directory $STATS_DIR"
