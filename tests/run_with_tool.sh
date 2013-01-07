#!/bin/sh -e

. `dirname "$0"`/test.include

PROG="$1"
shift

case "$PROG" in
    *.sh)
        "$PROG" "$@" || exit $?
        ;;

    *)
        test -n "$TEST_LOG_NAME" || TEST_LOG_NAME=check
        test -n "$TEST_LOG_DIR" || TEST_LOG_DIR=`dirname "$PROG"`
        test -n "$STRICT_CHECKS" || STRICT_CHECKS=1
        run `basename "$PROG"` "$PROG" "$@" || exit $?
        ;;
esac
