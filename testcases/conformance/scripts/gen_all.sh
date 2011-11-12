#!/bin/bash
#
# gen_all.sh - create all conformance test cases: certs, roas, crls, mfts
#

# Set up RPKI environment variables if not already done.
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../../../envir.setup

# Safe bash shell scripting practices
. $RPKI_ROOT/trap_errors

# NOTES

# Set up paths to ASN.1 tools.
CGTOOLS=$RPKI_ROOT/cg/tools	# Charlie Gardiner's tools
CFSCRIPTS=$RPKI_ROOT/testcases/conformance/scripts # conformance scripts
ensure_file_exists $CGTOOLS/rr
hash sed

# Build trust anchors
cd $RPKI_ROOT/testcases/conformance/raw
for f in badRootBadAKI badRootBadCRLDP badRootNameDiff root
do
    $CGTOOLS/rr < $f.raw > $f.cer
done

# Build CRL
$CGTOOLS/rr < root.crl.raw > root/root.crl

# Generate all types of conformance cases
$CFSCRIPTS/gen_all_certs.sh -P
$CFSCRIPTS/gen_all_CMSs.sh -P
$CFSCRIPTS/gen_all_CRLs.sh -P
$CFSCRIPTS/gen_all_MFTs.sh -P

# Copy to output directory
cd $RPKI_ROOT/testcases/conformance
mkdir -p output
cp raw/*.cer output/
cp -r raw/root output/
find output -name '*.ee.cer' -delete
find output -name '*.mft.cer' -delete
find output -name '.gitignore' -delete

# Generate final manifest
cd output
$CFSCRIPTS/gen_mft.sh \
    root \
    1 \
    1 \
    ../raw/root.cer \
    rsync://rpki.bbn.com/conformance/root.cer \
    ../raw/root.p15 \
    rsync://rpki.bbn.com/conformance/root/root.crl \
    root/*.cer root/*.roa
rm root.mft.cer root.mft.p15
mv root.mft root/
