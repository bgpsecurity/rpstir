#!/bin/bash -e
#
# run the chaser, one argument is the name of the original config file
#   used for doing the rsync_pull

# set environment variables if not set
THIS_SCRIPT_DIR=`dirname "$0"`
. $THIS_SCRIPT_DIR/../envir.setup

CHASER="$RPKI_ROOT/proto/chaser"
RSYNC_CORD_CONF="$RPKI_ROOT/rsync_cord.config"
BAD_URI_CHARS='['\''",;&(){}|<>!$`\\[:space:][:cntrl:]]\|\[\|\]'

OLD_LIST="`mktemp`"
CUR_LIST="`mktemp`"

$CHASER "$@" > "$CUR_LIST"

while ! cmp -s "$OLD_LIST" "$CUR_LIST"; do
	rm -f "$RSYNC_CORD_CONF"

	echo "RSYNC=\"`which rsync`\"" >> "$RSYNC_CORD_CONF"
	echo "REPOSITORY=\"$RPKI_ROOT/REPOSITORY\"" >> "$RSYNC_CORD_CONF"
	echo "LOGS=\"$RPKI_ROOT/LOGS\"" >> "$RSYNC_CORD_CONF"

	DONE_URI=0
	printf "DIRS=\"" >> "$RSYNC_CORD_CONF"
	while read -r -d "" URI; do
		if printf "%s" "$URI" | grep -q "$BAD_URI_CHARS"; then
			echo >&2 "Discarding URI: $URI"
		elif test -n "$URI"
			if test $DONE_URI -eq 0; then
				DONE_URI=1
			else
				printf " " >> "$RSYNC_CORD_CONF"
			fi
			printf "%s" "$URI" | sed 's!^rsync://!!i' | sed 's!/$!!' >> "$RSYNC_CORD_CONF"
		fi
	done < "$CUR_LIST"
	echo "\"" >> "$RSYNC_CORD_CONF"

	python "$RPKI_ROOT"/rsync_aur/rsync_cord.py -d -c "$RSYNC_CORD_CONF" -t "$RPKI_TCOUNT" -p "$RPKI_LISTPORT"

	rm -f "$OLD_LIST"
	OLD_LIST="$CUR_LIST"
	CUR_LIST="`mktemp`"
	$CHASER "$@" > "$CUR_LIST"
done

rm -f "$OLD_LIST" "$CUR_LIST"
