#!/bin/sh -e

cd "`dirname "$0"`"

. ../../envir.setup


SERVER="$RPKI_ROOT/rtr/rtrd"
CLIENT="$RPKI_ROOT/rtr/rtr-test-client"
LOGS="rtrd rtr-test-client"
PORT=1234

compare () {
	name="$1"
	printf >&2 "comparing \"%s\" to \"%s\"... " "$name" "$name.correct"
	if diff -uN "$name" "$name.correct" > "$name.diff" 2>/dev/null; then
		echo >&2 "success."
	else
		echo >&2 "failed!"
		echo >&2 "See \"$name.diff\" for the differences."
		exit 1
	fi
}

start_test () {
	TEST="$1"

	for LOG in $LOGS; do
		rm -f "$LOG.log" "$LOG.$TEST.log"
	done

	"$SERVER" > rtrd.log 2>&1 &
	SERVER_PID=$!
	sleep 1
}

stop_test () {
	TEST="$1"

	kill $SERVER_PID
	wait $SERVER_PID || true

	for LOG in $LOGS; do
		mv -f "$LOG.log" "$LOG.$TEST.log"
		compare "$LOG.$TEST.log"
	done
}

start_test simple
cat commands | "$CLIENT" send | nc localhost "$PORT" | "$CLIENT" recv
stop_test simple
