#!/bin/bash -x
#
# ***** BEGIN LICENSE BLOCK *****
#
#  BBN Address and AS Number PKI Database/repository software
#  Version 4.0
#
#  US government users are permitted unrestricted rights as
#  defined in the FAR.
#
#  This software is distributed on an "AS IS" basis, WITHOUT
#  WARRANTY OF ANY KIND, either express or implied.
#
#  Copyright (C) Raytheon BBN Technologies 2011.  All Rights Reserved.
#
#  Contributor(s): Charlie Gardiner, Andrew Chi
#
#  ***** END LICENSE BLOCK ***** */

# make_test_cert.sh - manually create certificate for RPKI syntax
#                     conformance test

# This script creates a certificate, prompts the user multiple times
# to interactively edit (e.g., in order to introduce errors), and
# captures those edits in ".patch" files (output of diff -u).  Later,
# patch_test_cert.sh can replay the creation process by automatically
# applying those patch files without user intervention.

# Set up RPKI environment variables if not already done.
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../../../envir.setup

# Safe bash shell scripting practices
set -o errexit			# exit if anything fails
set -o errtrace			# shell functions inherit 'ERR' trap
trap "echo Error encountered during execution of $0 1>&2" ERR

# Usage
usage ( ) {
    usagestr="
Usage: $0 [options] <filestem> <serial>

Options:
  -k keyfile\tRoot's key (default = ...conformance/raw/root.p15)
  -o outdir \tOutput directory (default = CWD)
  -t template\tTemplate cert (default = ...conformance/raw/templates/goodCert.raw)
  -h        \tDisplay this help file

This script creates a certificate, prompts the user multiple times to
interactively edit (e.g., in order to introduce errors), and captures
those edits in '.patch' files (output of diff -u).  Later,
patch_test_cert.sh can replay the creation process by automatically
applying those patch files instead of prompting for user intervention.

This tool assumes the repository structure in the diagram below.  It
creates only the certificate labeled 'Child'.  In the Child's SIA, the
accessMethod id-ad-rpkiManifest will have an accessLocation of
rsync://rpki.bbn.com/conformance/root/empty/doesNotExist.mft, and that
manifest will be intentionally omitted from the directory named
'empty'.  This allows us to reuse the same empty directory as the SIA
for the large number of certificates that we will generate using this
script.


               +-----------------------------------+
               | rsync://rpki.bbn.com/conformance/ |
               |     +--------+                    |
         +---------->|  Root  |                    |
         |     |     |  cert  |                    |
         |  +---------- SIA   |                    |
         |  |  |     +--------+                    |
         |  |  +-----------------------------------+
         |  |
         |  |
         |  |  +----------------------------------------+
         |  |  | rsync://rpki.bbn.com/conformance/root/ |
         |  +->|   +--------+     +------------+        |
         |     |   | *Child |     | CRL issued |        |
         |     |   | CRLDP------->| by Root    |        |
         +----------- AIA   |     | root.crl   |        |
               |   |  SIA------+  +------------+        |
               |   +--------+  |  +-----------------+   |
               |               |  | Manifest issued |   |
               |               |  | by Root         |   |
               | Root's Repo   |  | root.mft        |   |
               | Directory     |  +-----------------+   |
               +---------------|------------------------+
                               |
                               V
               +----------------------------------------------+
               | rsync://rpki.bbn.com/conformance/root/empty/ |
               |                                              |
               | Empty Directory (MFT intentionally omitted)  |
               +----------------------------------------------+

Inputs:
  filestem - subject name (and filename stem) for 'Child' to be created
  serial - serial number for 'Child' to be created
  keyfile - (optional) local path to root key pair
  outdir - (optional) local path to root's repo directory
  template - (optional) template cert for Child. WARNING: use this
             option at your own risk.  Substituting a non-default
             template cert will probably mess up search
             paths/validation.  This option is meant to provide
             compatibility if the templates directory changes.

Outputs:
  child CA certificate - AS/IP resources are hardcoded in goodCert.raw template
  patch files - manual edits are saved as diff output in
                'badCert<filestem>.stageN.patch' (N=0..1)
    "
    printf "${usagestr}\n"
    exit 1
}

# NOTES

# 1. Variable naming convention -- preset constants and command line
# arguments are in ALL_CAPS.  Derived/computed values are in
# lower_case.

# 2. Assumes write-access to current directory even though the output
# directory will be different.

# Set up paths to ASN.1 tools.
CGTOOLS=$RPKI_ROOT/cg/tools	# Charlie Gardiner's tools

# Options and defaults
OUTPUT_DIR="."
ROOT_KEY_PATH="$RPKI_ROOT/testcases/conformance/raw/root.p15"
TEMPLATE_CERT_RAW="$RPKI_ROOT/testcases/conformance/raw/templates/goodCert.raw"

# Process command line arguments.
while getopts b:o:h opt
do
  case $opt in
      k)
	  ROOT_KEY_PATH=$OPTARG
	  ;;
      o)
	  OUTPUT_DIR=$OPTARG
	  ;;
      t)
	  TEMPLATE_CERT_RAW=$OPTARG
	  ;;
      h)
	  usage
	  ;;
  esac
done
shift $((OPTIND - 1))
if [ $# = "2" ]
then
    FILESTEM=$1
    SERIAL=$2
else
    usage
fi

###############################################################################
# Computed Variables
###############################################################################

child_name=badCert${FILESTEM}


###############################################################################
# Check for prerequisite tools and files
###############################################################################

ensure_file ( ) {
    if [ ! -e "$1" ]
    then
	echo "Error: file not found - $1" 1>&2
	exit 1
    fi
}

if [ ! -d "$OUTPUT_DIR" ]
then
    echo "Error: output directory not found - $OUTPUT_DIR" 1>&2
    exit 1
fi

ensure_file $ROOT_KEY_PATH
ensure_file $TEMPLATE_CERT_RAW
ensure_file $CGTOOLS/rr
ensure_file $CGTOOLS/put_sernum
ensure_file $CGTOOLS/dump_smart
ensure_file $CGTOOLS/sign_cert


###############################################################################
# Generate Child cert
###############################################################################

# Customize w/ serial number and subject name (based on $child_name)
cp ${TEMPLATE_CERT_RAW} ${child_name}.raw
${CGTOOLS}/rr <${child_name}.raw >${child_name}.cer
${CGTOOLS}/put_sernum ${child_name}.cer ${SERIAL}
${CGTOOLS}/dump_smart ${child_name}.cer >${child_name}.raw

# Manually modify (pre-signing): can be no-op
cp ${child_name}.raw ${child_name}.raw.old
vi ${child_name}.raw
diff -u ${child_name}.raw.old ${child_name}.raw >${child_name}.stage0.patch \
    || true

# Sign it
${CGTOOLS}/rr <${child_name}.raw >${child_name}.blb
${CGTOOLS}/sign_cert ${child_name}.blb ${ROOT_KEY_PATH}
mv ${child_name}.blb ${child_name}.cer
${CGTOOLS}/dump_smart ${child_name}.cer >${child_name}.raw

# Manually modify (post-signing): can be no-op
cp ${child_name}.raw ${child_name}.raw.old
vi ${child_name}.raw
diff -u ${child_name}.raw.old ${child_name}.raw >${child_name}.stage1.patch \
    || true

# Convert back into DER-encoded binary.
${CGTOOLS}/rr <${child_name}.raw >${child_name}.cer

# Clean-up
rm ${child_name}.raw
rm ${child_name}.raw.old

# Move to output directory
if [ ${OUTPUT_DIR} != "." ]
then
    mv ${child_name}.cer ${OUTPUT_DIR}/
    mv ${child_name}.stage0.patch ${OUTPUT_DIR}/
    mv ${child_name}.stage1.patch ${OUTPUT_DIR}/
fi
