#!/bin/sh -e

# XXX: remove this once this script works
exit 0

THIS_SCRIPT_DIR=`dirname "$0"`
. "$THIS_SCRIPT_DIR/../../../envir.setup"

cd "$THIS_SCRIPT_DIR"/..

./scripts/gen_all.sh

cd output

add_file () {
	TYPE="$1" # "good" or "bad"
	FLAGS="$2" # -f or -F
	FILE="$3" # file to add

	if test x"$TYPE" = "bad"; then
		if "$RPKI_ROOT/proto/rcli" -y $FLAGS "$FILE"; then
			echo >&2 "Error: adding bad file $FILE succeeded"
			exit 1
		fi
	else
		if ! "$RPKI_ROOT/proto/rcli" -y $FLAGS "$FILE"; then
			echo >&2 "Error: adding good file $FILE failed"
			exit 1
		fi
	fi
}

init_db () {
	"$RPKI_ROOT/run_scripts/initDB.sh"
}

reset_db () {
	"$RPKI_ROOT/proto/rcli" -x -t "$RPKI_ROOT/REPOSITORY" -y
	add_file good -F root.cer
	add_file good -f root/root.crl
	add_file good -f root/root.mft
}


init_db

for BAD_ROOT in badRoot*.cer; do
	reset_db
	add_file bad -F "$BAD_ROOT"
done

cd root

for GOOD_SINGLE_FILE in good*; do
	reset_db
	add_file good -f "$GOOD_SINGLE_FILE"
done

for BAD_SINGLE_FILE in bad*; do
	reset_db
	add_file bad -f "$BAD_SINGLE_FILE"
done

for CRL_CERT in CRL*.cer; do
	CRL_NAME=`basename "$CRL_CERT" .cer`
	reset_db
	add_file good -f "$CRL_CERT"
	add_file good -f "$CRL_NAME/$CRL_NAME.mft"
	add_file bad -f "$CRL_NAME/bad$CRL_NAME.crl"
done

for MFT_CERT in MFT*.cer; do
	MFT_NAME=`basename "$MFT_CERT" .cer`
	reset_db
	add_file good -f "$MFT_CERT"
	add_file good -f "$MFT_NAME/$MFT_NAME.crl"
	add_file bad -f "$MFT_NAME/bad$MFT_NAME.mft"
done
