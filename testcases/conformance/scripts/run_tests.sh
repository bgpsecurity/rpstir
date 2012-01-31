#!/bin/sh -e

# XXX: remove this once this script works
exit 0

THIS_SCRIPT_DIR=`dirname "$0"`
. "$THIS_SCRIPT_DIR/../../../envir.setup"

cd "$THIS_SCRIPT_DIR"/..

./scripts/gen_all.sh

init_db () {
	"$RPKI_ROOT/run_scripts/initDB.sh"
	"$RPKI_ROOT/proto/rcli" -y -F raw/root.cer
}

reset_db () {
	"$RPKI_ROOT/proto/rcli" -x -t "$RPKI_ROOT/REPOSITORY" -y
	"$RPKI_ROOT/proto/rcli" -y -F raw/root.cer
}

init_db

for BAD_FILE in raw/root/bad*; do
	reset_db
	if "$RPKI_ROOT/proto/rcli" -y -f "$BAD_FILE"; then
		echo >&2 "Error: adding bad file $BAD_FILE succeeded"
		exit 1
	fi
done

for GOOD_FILE in raw/root/good*; do
	reset_db
	if ! "$RPKI_ROOT/proto/rcli" -y -f "$GOOD_FILE"; then
		echo >&2 "Error: adding good file $GOOD_FILE failed"
		exit 1
	fi
done
