#!/bin/bash -e

cd $RPKI_ROOT

TAL_FILES=""
TAL_URI_FILES=""

print_usage () {
	echo >&2 "Usage: $0 <TAL uri> | <TAL file> ..."
	echo >&2
	echo >&2 "Run RPSTIR on the specified TAL URIs or files."
}

for TAL in "$@"; do
	if test "$TAL" = "-h" -o "$TAL" = "--help"; then
		print_usage
		exit 1
	elif test -f "$TAL"; then
		echo >&2 "Using TAL $TAL"
		TAL_FILES="$TAL_FILES $TAL"
	else
		TAL_FILE="`mktemp --suffix=.tal`"
		echo >&2 "Downloading $TAL to $TAL_FILE"
		wget "$TAL" -O "$TAL_FILE"
		echo >&2 "Using TAL $TAL_FILE from $TAL"
		TAL_URI_FILES="$TAL_URI_FILES $TAL_FILE"
	fi
done

if test -z "$TAL_FILES$TAL_URI_FILES"; then
	echo >&2 "No TAL files or URIs specified"
	echo >&2
	print_usage
	exit 1
fi

# Clear file cache and database
rm -rf REPOSITORY LOGS chaser.log rcli.log rsync_aur.log query.log
mkdir -p REPOSITORY
mkdir -p LOGS
./run_scripts/initDB.sh

# Start validator component in separate window
./run_scripts/loader.sh &
LOADER_PID=$!
sleep 1

# Out-of-band initialization of trust anchor
./run_scripts/updateTA.py $TAL_FILES $TAL_URI_FILES

# Chase downward from trust anchor(s) using rsync
./run_scripts/chaser.sh

kill "$LOADER_PID"
wait "$LOADER_PID"

rm -f "$TAL_URI_FILES"
