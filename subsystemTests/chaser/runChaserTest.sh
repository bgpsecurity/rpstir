#!/bin/sh -e

cd "`dirname "$0"`"
. ../../envir.setup
CMD=./proto/chaser

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
add_valgrind () {
	if test x"$VALGRIND" = x1; then
		CMD="valgrind --log-file=valgrind.log --track-fds=full \
        --leak-check=full --error-exitcode=1 $CMD"
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
CMD="$RPKI_ROOT/proto/chaser -t -f input.subsume"
add_valgrind
start_test subsume
$CMD > response.log
stop_test subsume

#===============================================================================
CMD="$RPKI_ROOT/proto/chaser -t -f input.max_length"
add_valgrind
start_test max_length
$CMD > response.log
stop_test max_length

#===============================================================================
CMD="$RPKI_ROOT/proto/chaser -t -f input.collapse_slash_dot"
add_valgrind
start_test collapse_slash_dot
$CMD > response.log
stop_test collapse_slash_dot

#===============================================================================
CMD="$RPKI_ROOT/proto/chaser -t -f input.collapse_dots"
add_valgrind
start_test collapse_dots
$CMD > response.log
stop_test collapse_dots

#===============================================================================
CMD="$RPKI_ROOT/proto/chaser -t -f input.collapse_slashes"
add_valgrind
start_test collapse_slashes
$CMD > response.log
stop_test collapse_slashes

#===============================================================================
#    Tests
#-------------------------------------------------------------------------------
: <<'END'
Properly distinguish crldps based on next_upd?

Correct output for cmd-line combinations?

Test limit of realloc of uris[].

END

