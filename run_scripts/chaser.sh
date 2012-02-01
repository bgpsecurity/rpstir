#!/bin/sh -e
#
# run the chaser, one argument is the name of the original config file
#   used for doing the rsync_pull

# set environment variables if not set
THIS_SCRIPT_DIR=`dirname "$0"`
. $THIS_SCRIPT_DIR/../envir.setup

CHASER="$RPKI_ROOT/proto/chaser"
RSYNC_CORD_CONF="$RPKI_ROOT/rsync_cord.config"

OLD_LIST="`mktemp`"
CUR_LIST="`mktemp`"

$CHASER "$@" > "$CUR_LIST"

while ! cmp -s "$OLD_LIST" "$CUR_LIST"; do
	rm -f "$RSYNC_CORD_CONF"
	# TODO: fill in $RSYNC_CORD_CONF from $CUR_LIST
	python "$RPKI_ROOT"/rsync_aur/rsync_cord.py -d -c "$RSYNC_CORD_CONF" -t "$RPKI_TCOUNT" -p "$RPKI_LISTPORT"

	rm -f "$OLD_LIST"
	OLD_LIST="$CUR_LIST"
	CUR_LIST="`mktemp`"
	$CHASER "$@" > "$CUR_LIST"
done

rm -f "$OLD_LIST" "$CUR_LIST"
