#!/bin/sh -e

cd `dirname "$0"`

. ../../../envir.setup

OUTDIR="`pwd`/empty_manifest"
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
	sia="r:rsync://example.com/rpki/,m:rsync://example.com/rpki/empty_manifest.mft" \
	ipv4="0.0.0.0/0" \
	ipv6="::/0" \
	as=0-4294967295

"$GEN_KEY" "$OUTDIR/empty_manifest.mft.ee.p15" 2048
"$CREATE_OBJECT" CERT \
	outputfilename="$OUTDIR/empty_manifest.mft.ee.cer" \
	parentcertfile="$OUTDIR/root.cer" \
	parentkeyfile="$OUTDIR/root.p15" \
	subjkeyfile="$OUTDIR/empty_manifest.mft.ee.p15" \
	type=EE \
	notbefore=120101010101Z \
	notafter=490101010101Z \
	serial=1 \
	subject=empty_manifest-mft-ee \
	crldp=rsync://example.com/rpki/invalid.crl \
	aia=rsync://example.com/rpki/root.cer \
	sia="s:rsync://example.com/rpki/empty_manifest.mft" \
	ipv4=inherit \
	ipv6=inherit \
	as=inherit
"$CREATE_OBJECT" MANIFEST \
	outputfilename="$OUTDIR/empty_manifest.mft" \
	EECertLocation="$OUTDIR/empty_manifest.mft.ee.cer" \
	EEKeyLocation="$OUTDIR/empty_manifest.mft.ee.p15" \
	thisUpdate=20120101010101Z \
	nextUpdate=20490101010101Z \
	manNum=1 \
	fileList=""
