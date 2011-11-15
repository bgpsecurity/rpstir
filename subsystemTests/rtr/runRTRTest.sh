#!/bin/bash

cd "`dirname "$0"`"

. ../../envir.setup
. "$RPKI_ROOT/trap_errors"


SERVER="$RPKI_ROOT/rtr/rtrd"
CLIENT="$RPKI_ROOT/rtr/rtr-client"
PORT=1234


"$SERVER" &
SERVER_PID=$!

compare () {
	name="`shift`"
	printf >&2 "comparing \"%s\" to \"%s\"... " "$name" "$name.correct"
	diff -u "$name" "$name.correct" > "$name.diff"
	if test -s "$name.diff"; then
		echo >&2 "failed!"
		echo >&2 "See \"$name.diff\" for the differences."
		exit 1
	else
		echo >&2 "success."
	fi
}

"$CLIENT" send | nc localhost "$PORT" | "$CLIENT" recv <<__EOF__
reset
serial 0 5
__EOF__

compare rtr-client.log

kill $SERVER_PID
wait $SERVER_PID
