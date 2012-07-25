#!/bin/sh -e

cd `dirname "$0"`

. ../../../../etc/envir.setup

OUTDIR="`pwd`/empty_manifest"
rm -rf "$OUTDIR"
mkdir "$OUTDIR"

TEST_LOG_NAME=empty_manifest
TEST_LOG_DIR="$OUTDIR"
. "$RPKI_ROOT/tests/test.include"


fail () {
	echo "$@"
	exit 1
}


run "gen_key-root" gen_key "$OUTDIR/root.p15" 2048 \
	|| fail "gen_key root.p15 failed"
run "create_object-root" create_object CERT \
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
	as=0-4294967295 \
	|| fail "create_object root.cer failed"

run "gen_key-mft-ee" gen_key "$OUTDIR/empty_manifest.mft.ee.p15" 2048 \
	|| fail "gen_key empty_manifest.mft.ee.p15 failed"
run "create_object-mft-ee" create_object CERT \
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
	as=inherit \
	|| fail "create_object empty_manifest.mft.ee.cer failed"
run "create_object-mft" create_object MANIFEST \
	outputfilename="$OUTDIR/empty_manifest.mft" \
	EECertLocation="$OUTDIR/empty_manifest.mft.ee.cer" \
	EEKeyLocation="$OUTDIR/empty_manifest.mft.ee.p15" \
	thisUpdate=20120101010101Z \
	nextUpdate=20490101010101Z \
	manNum=1 \
	fileList="" \
	|| fail "create_object empty_manifest.mft failed"
