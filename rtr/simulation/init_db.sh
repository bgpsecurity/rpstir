#!/bin/sh -e

. "`dirname "$0"`/../../envir.setup"

if ! test $# -eq 1 -a "$1" -gt 0; then
	echo >&2 "Usage: $0 <number of thousands of prefixes to use>"
	exit 1
fi

NUM_THOUSANDS="$1"

echo 'TRUNCATE TABLE rtr_session;' | $RPKI_MYSQL_CMD
echo 'TRUNCATE TABLE rtr_update;' | $RPKI_MYSQL_CMD
echo 'TRUNCATE TABLE rtr_full;' | $RPKI_MYSQL_CMD
echo 'TRUNCATE TABLE rtr_incremental;' | $RPKI_MYSQL_CMD

echo 'INSERT INTO rtr_session (session_id) VALUES (FLOOR(RAND() * (1 << 16)));' | $RPKI_MYSQL_CMD

echo 'DROP TABLE IF EXISTS rtr_simulation_count;' | $RPKI_MYSQL_CMD
echo 'CREATE TABLE rtr_simulation_count (col TINYINT DEFAULT 0);' | $RPKI_MYSQL_CMD

INSERT_THOUSAND='INSERT INTO rtr_simulation_count VALUES (0)'
for __discard in `seq 2 1000`; do
	INSERT_THOUSAND="$INSERT_THOUSAND,(0)"
done
INSERT_THOUSAND="$INSERT_THOUSAND;"

for __discard in `seq 1 "$NUM_THOUSANDS"`; do
	echo "$INSERT_THOUSAND" | $RPKI_MYSQL_CMD
done
