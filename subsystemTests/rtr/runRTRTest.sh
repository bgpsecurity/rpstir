#!/bin/sh -e

cd "`dirname "$0"`"

. ../../envir.setup


SERVER="$RPKI_ROOT/rtr/rtrd"
CLIENT="$RPKI_ROOT/rtr/rtr-test-client"
LOGS="rtrd rtr-test-client"
PORT=1234
NONCE=42
WRONG_NONCE=4242

alias client="$CLIENT send | nc -q 1 localhost $PORT | $CLIENT recv"

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

init () {
	"$RPKI_ROOT"/proto/rcli -x -t . -y
	echo "INSERT INTO rtr_nonce VALUES ($NONCE);" | $RPKI_MYSQL_CMD
}

make_serial () {
	PREV_SERIAL="$1" # a number or empty string if this is the first call
	SERIAL="$2"
	FIRST_ASN="$3"
	LAST_ASN="$4"

	test "$FIRST_ASN" -ge 1
	test "$LAST_ASN" -le 255
	test "$FIRST_ASN" -le "$LAST_ASN"

	COMMAND_FILE="`mktemp`"

	for ASN in `seq "$FIRST_ASN" "$LAST_ASN"`; do
		for IP_LAST_OCTET in `seq 1 "$ASN"`; do
			printf 'INSERT INTO rtr_full (serial_num, asn, ip_addr) VALUES (%u, %u, '\''%u.0.0.%u'\'');\n' \
				"$SERIAL" "$ASN" "$ASN" "$IP_LAST_OCTET" >> "$COMMAND_FILE"
			printf 'INSERT INTO rtr_full (serial_num, asn, ip_addr) VALUES (%u, %u, '\''%02x::%02x'\'');\n' \
				"$SERIAL" "$ASN" "$ASN" "$IP_LAST_OCTET" >> "$COMMAND_FILE"
		done
	done

	if test x"$PREV_SERIAL" != x; then
		echo \
			"INSERT INTO rtr_incremental (serial_num, is_announce, asn, ip_addr)" \
			"SELECT DISTINCT $PREV_SERIAL, 1, t1.asn, t1.ip_addr" \
			"FROM rtr_full AS t1" \
			"LEFT JOIN rtr_full AS t2 ON t2.serial_num = $PREV_SERIAL AND t2.asn = t1.asn AND t2.ip_addr = t1.ip_addr" \
			"WHERE t1.serial_num = $SERIAL AND t2.serial_num IS NULL;" \
			>> "$COMMAND_FILE"
		echo \
			"INSERT INTO rtr_incremental (serial_num, is_announce, asn, ip_addr)" \
			"SELECT DISTINCT $PREV_SERIAL, 0, t1.asn, t1.ip_addr" \
			"FROM rtr_full AS t1" \
			"LEFT JOIN rtr_full AS t2 ON t2.serial_num = $SERIAL AND t2.asn = t1.asn AND t2.ip_addr = t1.ip_addr" \
			"WHERE t1.serial_num = $PREV_SERIAL AND t2.serial_num IS NULL;" \
			>> "$COMMAND_FILE"
	fi

	printf 'INSERT INTO rtr_update VALUES (%u, now());\n' "$SERIAL" >> "$COMMAND_FILE"

	$RPKI_MYSQL_CMD < "$COMMAND_FILE"

	rm -f "$COMMAND_FILE"
}

drop_serial () {
	SERIAL="$1"

	COMMAND_FILE="`mktemp`"

	printf 'DELETE FROM rtr_update WHERE serial_num = %u;\n' "$SERIAL" >> "$COMMAND_FILE"
	printf 'DELETE FROM rtr_full WHERE serial_num = %u;\n' "$SERIAL" >> "$COMMAND_FILE"
	printf 'DELETE FROM rtr_incremental WHERE serial_num = %u;\n' "$SERIAL" >> "$COMMAND_FILE"

	$RPKI_MYSQL_CMD < "$COMMAND_FILE"

	rm -f "$COMMAND_FILE"
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


init

# Comments after queries indicate what's expected to be returned.

start_test reset_query_first
make_serial "" 5 1 30
echo "reset" | client # all data for serial 5
stop_test reset_query_first

start_test serial_queries
echo "serial $WRONG_NONCE 5" | client # Cache Reset
echo "serial $NONCE 5" | client # empty set
make_serial 5 7 2 32
echo "serial $NONCE 5" | client # difference from 5 to 7
make_serial 7 8 1 20
drop_serial 5
echo "serial $NONCE 5" | client # difference from 5 to 8
drop_serial 7
echo "serial $NONCE 5" | client # Cache Reset
echo "serial $NONCE 7" | client # difference from 7 to 8
stop_test serial_queries

start_test error_conditions
# TODO
stop_test error_conditions

start_test reset_query_last
echo "reset" | client # all data for serial 8
stop_test reset_query_last
