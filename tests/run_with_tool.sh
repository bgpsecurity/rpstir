#!/bin/sh -e

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
        . `dirname "$0"`/../subsystemTests/test.include

        run "$PROG" ./"$PROG" "$@" || exit $?
        ;;
esac
