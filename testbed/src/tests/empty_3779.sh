#!/bin/sh -e

cd `dirname "$0"`

. ../../../envir.setup

OUTDIR="`pwd`/empty_3779"
rm -rf "$OUTDIR"
mkdir "$OUTDIR"

cd "$RPKI_ROOT/testbed/src"

GEN_KEY="$RPKI_ROOT/cg/tools/gen_key"
CREATE_OBJECT="$RPKI_ROOT/testbed/src/create_object"

"$GEN_KEY" "$OUTDIR/root.p15" 2048
"$CREATE_OBJECT" CERT \
	outputfilename="$OUTDIR/root.cer" \
	subjkeyfile="$OUTDIR/root.p15" \
	type=CA \
	selfsigned=true \
	serial=1 \
	issuer="root" \
	subject="root" \
	notbefore=120101010101Z \
	notafter=490101010101Z \
	sia="r:rsync://example.com/rpki/,m:rsync://example.com/rpki/empty_3779.mft"
