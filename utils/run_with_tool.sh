#!/bin/sh -e

TEST_LOG_NAME=check
STRICT_CHECKS=1
. `dirname "$0"`/../subsystemTests/test.include

PROG=`basename "$1"`
cd `dirname "$1"`
shift

run "$PROG" ./"$PROG" "$@" || exit $?
