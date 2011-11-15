#!/bin/sh -e

cd "`dirname "$0"`"

. ../../envir.setup


SERVER="$RPKI_ROOT/rtr/rtrd"
CLIENT="$RPKI_ROOT/rtr/rtr-test-client"
LOGS="rtrd.log rtr-test-client.log"
PORT=1234


rm -f $LOGS


"$SERVER" &
SERVER_PID=$!
sleep 1

cleanup () {
	kill $SERVER_PID
	wait $SERVER_PID
}

compare () {
	name="$1"
	printf >&2 "comparing \"%s\" to \"%s\"... " "$name" "$name.correct"
	if diff -uN "$name" "$name.correct" > "$name.diff" 2>/dev/null; then
		echo >&2 "success."
	else
		echo >&2 "failed!"
		echo >&2 "See \"$name.diff\" for the differences."
		cleanup
		exit 1
	fi
}

cat commands | "$CLIENT" send | nc localhost "$PORT" | "$CLIENT" recv
for LOG in $LOGS; do
	compare "$LOG"
done

cleanup
