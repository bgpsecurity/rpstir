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
	else
		echo >&2 "failed!"
		echo >&2 "See \"$name.diff\" for the differences."
		exit 1
	fi
}

#===============================================================================
add_valgrind () {
	if test x"$VALGRIND" = x1; then
		CMD=valgrind --log-file=valgrind.log --track-fds=full \
        --leak-check=full --error-exitcode=1 "$CMD"
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
#    Tests
#-------------------------------------------------------------------------------
: <<'END'
    Is x subsumed by y?
rsync://example.com/a
rsync://example.com/a/
rsync://example.com/a/b/c
rsync://example.com/a/c/b
rsync://example.com/a/b/c/d
rsync://example.com/abcdefg/b

    Properly collapse "..".
rsync://foo.com/../
rsync://foo.com/a/../b
rsync://foo.com/a/../..
rsync://foo.com/a/.../b

    Properly collapse "//".
rsync://foo.com/a//
rsync://foo.com/a//b
rsync://foo.com/a///b
rsync://foo.com/a//////////////b
rsync://foo.com/a///b///c/

    Properly collapse "/./".
rsync://foo.com/./
rsync://foo.com/a/./
rsync://foo.com/a/./b/c
rsync://foo.com/a/./b/./c

    Handle random chars in uri path.

    Properly distinguish crldps based on next_upd?

    Correct output for cmd-line combinations?

    Can crafted bad uri crash the program?  or get thru?

    Test limit of realloc of uris[].

    Add multiple uris that are semicolon delimited on a single line.

    Various off-by-one errors.
uris have lengths 1023, 1024.  One should pass and the other be dropped.


END

