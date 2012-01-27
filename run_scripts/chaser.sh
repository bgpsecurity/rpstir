#!/bin/sh -e
#
# run the chaser, one argument is the name of the original config file
#   used for doing the rsync_pull

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../envir.setup

# XXX: check this command line, also make sure it outputs NULL-separated URIs only, in sorted order
CHASER="$RPKI_ROOT/proto/chaser ..."

OLD_LIST="`mktemp`"
CUR_LIST="`mktemp`"

$CHASER "$@" > "$CUR_LIST"

while ! cmp -s "$OLD_LIST" "$CUR_LIST"; do
	rsync, aur, rcli, etc "$CUR_LIST" # XXX

	mv "$CUR_LIST" "$OLD_LIST"
	$CHASER "$@" > "$CUR_LIST"
done

rm -f "$OLD_LIST" "$CUR_LIST"
