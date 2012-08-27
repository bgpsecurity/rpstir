#!/bin/sh -e

. `dirname "$0"`/test.include

PROG=`basename "$1"`
cd `dirname "$1"`
shift

case "$PROG" in
    *.sh)
        ./"$PROG" "$@" || exit $?
        ;;

    *)
        TEST_LOG_NAME=check
        STRICT_CHECKS=1
        run "$PROG" ./"$PROG" "$@" || exit $?
        ;;
esac
