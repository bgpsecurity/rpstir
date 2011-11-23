#/bin/sh -e

if test $# -le 0; then
	echo >&2 "Usage: $0 <file.c> | <file.h> ..."
	echo >&2 "Remove the license block from all files specified on the command line."
	exit 1
fi

AWK_FILE="`dirname "$0"`/remove_license_block-helper.awk"

for file in "$@"; do
	TMP="`mktemp`"
	echo >&2 "$file"
	awk -f "$AWK_FILE" < "$file" > "$TMP"
	mv "$TMP" "$file"
done
