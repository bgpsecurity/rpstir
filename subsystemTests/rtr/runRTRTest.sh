#!/bin/sh -e

cd "`dirname "$0"`"

. ../../envir.setup


SERVER="$RPKI_ROOT/rtr/rtrd"
CLIENT="$RPKI_ROOT/rtr/rtr-test-client"
PORT=1234
NONCE=42
WRONG_NONCE=4242

client_raw () {
	SUBTEST_NAME="$1"
	shift
	EXPECTED_RESULTS="$1"
	shift
	echo "--- $SUBTEST_NAME" | tee -a response.log
	echo "--- expecting: $EXPECTED_RESULTS" | tee -a response.log
	"$@" | "$CLIENT" client_one localhost $PORT | tee -a response.log
}

client () {
	COMMAND="$1"
	EXPECTED_RESULTS="$2"
	INPUT_PDU_FILE="`mktemp`"
	echo "$COMMAND" | "$CLIENT" write > "$INPUT_PDU_FILE"
	client_raw "$COMMAND" "$EXPECTED_RESULTS" cat "$INPUT_PDU_FILE"
	rm -f "$INPUT_PDU_FILE"
}


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
			printf 'INSERT INTO rtr_full (serial_num, asn, ip_addr) VALUES (%u, %u, '\''%u.%u.0.0/16'\'');\n' \
				"$SERIAL" "$ASN" "$ASN" "$IP_LAST_OCTET" >> "$COMMAND_FILE"
			printf 'INSERT INTO rtr_full (serial_num, asn, ip_addr) VALUES (%u, %u, '\''%u.0.%u.0/24(25)'\'');\n' \
				"$SERIAL" "$ASN" "$ASN" "$IP_LAST_OCTET" >> "$COMMAND_FILE"
			printf 'INSERT INTO rtr_full (serial_num, asn, ip_addr) VALUES (%u, %u, '\''%x::%x00/120'\'');\n' \
				"$SERIAL" "$ASN" "$ASN" "$IP_LAST_OCTET" >> "$COMMAND_FILE"
			printf 'INSERT INTO rtr_full (serial_num, asn, ip_addr) VALUES (%u, %u, '\''%x:%x::/32(127)'\'');\n' \
				"$SERIAL" "$ASN" "$ASN" "$IP_LAST_OCTET" >> "$COMMAND_FILE"
		done
	done

	if test x"$PREV_SERIAL" != x; then
		echo \
			"INSERT INTO rtr_incremental (serial_num, is_announce, asn, ip_addr)" \
			"SELECT DISTINCT $SERIAL, 1, t1.asn, t1.ip_addr" \
			"FROM rtr_full AS t1" \
			"LEFT JOIN rtr_full AS t2 ON t2.serial_num = $PREV_SERIAL AND t2.asn = t1.asn AND t2.ip_addr = t1.ip_addr" \
			"WHERE t1.serial_num = $SERIAL AND t2.serial_num IS NULL;" \
			>> "$COMMAND_FILE"
		echo \
			"INSERT INTO rtr_incremental (serial_num, is_announce, asn, ip_addr)" \
			"SELECT DISTINCT $SERIAL, 0, t1.asn, t1.ip_addr" \
			"FROM rtr_full AS t1" \
			"LEFT JOIN rtr_full AS t2 ON t2.serial_num = $SERIAL AND t2.asn = t1.asn AND t2.ip_addr = t1.ip_addr" \
			"WHERE t1.serial_num = $PREV_SERIAL AND t2.serial_num IS NULL;" \
			>> "$COMMAND_FILE"

		printf 'INSERT INTO rtr_update VALUES (%u, %u, now(), true);\n' "$SERIAL" "$PREV_SERIAL" >> "$COMMAND_FILE"
	else
		printf 'INSERT INTO rtr_update VALUES (%u, NULL, now(), true);\n' "$SERIAL" >> "$COMMAND_FILE"
	fi


	$RPKI_MYSQL_CMD < "$COMMAND_FILE"

	rm -f "$COMMAND_FILE"
}

drop_serial () {
	SERIAL="$1"

	COMMAND_FILE="`mktemp`"

	printf 'DELETE FROM rtr_update WHERE serial_num = %u;\n' "$SERIAL" >> "$COMMAND_FILE"
	printf 'DELETE FROM rtr_full WHERE serial_num = %u;\n' "$SERIAL" >> "$COMMAND_FILE"
	printf 'DELETE rtr_incremental FROM rtr_incremental LEFT JOIN rtr_update ON rtr_incremental.serial_num = rtr_update.serial_num WHERE rtr_update.prev_serial_num = %u;\n' "$SERIAL" >> "$COMMAND_FILE"
	printf 'UPDATE rtr_update SET prev_serial_num = NULL WHERE prev_serial_num = %u;\n' "$SERIAL" >> "$COMMAND_FILE"

	$RPKI_MYSQL_CMD < "$COMMAND_FILE"

	rm -f "$COMMAND_FILE"
}

start_test () {
	TEST="$1"

	rm -f "response.log" "response.$TEST.log"

	"$SERVER" &
	SERVER_PID=$!
	sleep 1
}

stop_test () {
	TEST="$1"

	kill $SERVER_PID
	wait $SERVER_PID || true

	mv -f "response.log" "response.$TEST.log"
	compare "response.$TEST.log"
}


init

# Comments after queries indicate what's expected to be returned.

start_test reset_query_first
make_serial "" 5 1 4
client "reset_query" "all data for serial 5"
stop_test reset_query_first

start_test serial_queries
client "serial_query $WRONG_NONCE 5" "Cache Reset"
client "serial_query $NONCE 5" "empty set"
make_serial 5 7 2 6
client "serial_query $NONCE 5" "difference from 5 to 7"
client "serial_query $NONCE 7" "empty set"
make_serial 7 8 1 3
client "serial_query $NONCE 5" "difference from 5 to 8"
client "serial_query $NONCE 6" "Cache Reset"
client "serial_query $NONCE 7" "difference from 7 to 8"
client "serial_query $NONCE 8" "empty set"
drop_serial 5
client "serial_query $NONCE 5" "Cache Reset"
client "serial_query $NONCE 6" "Cache Reset"
client "serial_query $NONCE 7" "difference from 7 to 8"
client "serial_query $NONCE 8" "empty set"
drop_serial 7
client "serial_query $NONCE 7" "Cache Reset"
client "serial_query $NONCE 8" "empty set"
stop_test serial_queries

start_test bad_pdus
TOTAL_BAD_PDUS="`./badPDUs.py length`"
for i in `seq 1 "$TOTAL_BAD_PDUS"`; do
	client_raw "Bad PDU #$i" "Error Report" ./badPDUs.py "$i"
done
stop_test bad_pdus

start_test bad_protocol_operation # erroneous use of valid PDUs
# TODO
stop_test bad_protocol_operation

start_test serial_notify
# TODO
stop_test serial_notify

start_test reset_query_last
client "reset_query" "all data for serial 8"
stop_test reset_query_last
