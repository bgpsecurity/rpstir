#!/bin/sh -e

cd "`dirname "$0"`"
. ../../../etc/envir.setup

TEST_LOG_NAME=chaser
STRICT_CHECKS=1
. "$CONFIG_ROOT_DIR"/tests/test.include

#===============================================================================
compare () {
	name="$1"
	printf >&2 "comparing \"%s\" to \"%s\"... " "$name" "$name.correct"
	if diff -u "$name.correct" "$name" > "$name.diff" 2>/dev/null; then
		echo >&2 "success."
        echo >&2
	else
		echo >&2 "failed!"
		echo >&2 "See \"$name.diff\" for the differences."
        echo >&2
		exit 1
	fi
}

#===============================================================================
start_test () {
	TEST="$1"

	rm -f "response.log" "response.$TEST.log"
	touch "response.log"
}

#===============================================================================
stop_test () {
	TEST="$1"

	mv -f "response.log" "response.$TEST.log"
	compare "response.$TEST.log"
}

#===============================================================================
for TEST_NAME in \
	subsume \
	max_length \
	collapse_slash_dot \
	collapse_dots \
	collapse_slashes \
	bad_chars
do
	start_test "$TEST_NAME"
	run "$TEST_NAME" chaser -s -t -f "input.$TEST_NAME" > response.log
	stop_test "$TEST_NAME"
done

#===============================================================================
#    More tests
#-------------------------------------------------------------------------------
# Properly distinguish crldps based on next_upd?
# Correct output for cmd-line combinations?
# Test limit of realloc of uris[].
