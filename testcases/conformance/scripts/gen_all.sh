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
ensure_file_exists $CGTOOLS/rr
hash sed

# Build trust anchors
cd $RPKI_ROOT/testcases/conformance/raw
for f in *.raw
do
    certname=`echo $f | sed -e 's/raw/cer/'`
    $CGTOOLS/rr < $f > $certname
done

# Generate all types of conformance cases
cd $RPKI_ROOT/testcases/conformance/scripts
./gen_all_certs.sh -P
./gen_all_CMSs.sh -P
./gen_all_CRLs.sh -P
./gen_all_MFTs.sh -P

# Copy to output directory
cd $RPKI_ROOT/testcases/conformance
mkdir -p output
cp raw/*.cer output/
cp -r raw/root output/
find output -name '*.ee.cer' -delete
find output -name '*.mft.cer' -delete
