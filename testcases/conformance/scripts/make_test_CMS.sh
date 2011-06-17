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

# Set up RPKI environment variables if not already done.
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../../../envir.setup

# Safe bash shell scripting practices
set -o errexit                  # exit if anything fails
set -o errtrace                 # shell functions inherit 'ERR' trap
trap "echo Error encountered during execution of $0 1>&2" ERR

# Usage
usage ( ) {
    usagestr="
Usage: $0 [options] <CMS/ROA> <filestem> <serial>

Options:
  -P        \tApply patches instead of prompting user to edit (default = false)
  -k keyfile\tRoot's key (default = ...conformance/raw/root.p15)
  -o outdir \tOutput directory (default = ...conformance/raw/root/)
  -p patchdir\tDirectory for saving/getting patches (default = .../conformance/raw/patches/)
  -h        \tDisplay this help file

This script creates a ROA (with embedded EE cert), prompts the user
multiple times to interactively edit (e.g., in order to introduce
errors), and captures those edits in '.patch' files (output of diff
-u).  Later, running $0 with the -P option can replay the creation
process by automatically applying those patch files instead of
prompting for user intervention.

This tool assumes the repository structure in the diagram below.  It
creates only the ROA (with embedded EE cert).  In the EE cert's SIA, the
accessMethod id-ad-signedObject will have an accessLocation of
rsync://rpki.bbn.com/conformance/root/subjname.roa .

               +-----------------------------------+
               | rsync://rpki.bbn.com/conformance/ |
               |     +--------+                    |
         +---------->|  Root  |                    |
         |     |     |  cert  |                    |
         |     |     |  SIA ----------------------------+
         |     |     +---|----+                    |    |
         |     +---------|-------------------------+    |
         |               |                              |
         |               V                              |
         |     +----------------------------------------|----+
         |     | rsync://rpki.bbn.com/conformance/root/ |    |
         |     |                                        V    |
         |     | +-------------+       +-----------------+   |
         |     | | *ROA issued |<--+   | Manifest issued |   |
         |     | | by Root     |   |   | by Root         |   |
         |     | | +--------+  |   |   | root.mft        |   |
         |     | | | EECert |  |   |   +-----------------+   |
         +----------- AIA   |  |   |                         |
               | | |  SIA ---------+       +------------+    |
               | | |  CRLDP--------------->| CRL issued |    |
               | | +--------+  |           | by Root    |    |
               | +-------------+           | root.crl   |    |
               |                           +------------+    |
               | Root's Repo                                 |
               | Directory                                   |
               +---------------------------------------------+

Inputs:
  class - ROA or CMS (i.e. whether this will be a ROA or CMS testcase)
  filestem - subject name (and filename stem) for ROA to be created
  serial - serial number for embedded EE certificate to be created
  -P - (optional) use patch mode for automatic insertion of errors
  keyfile - (optional) local path to root key pair
  outdir - (optional) local path to root's repo directory
  patchdir - (optional) local path to directory of patches

Outputs:
  ROA - AS/IP resources are hardcoded in goodEECert and goodROA templates
  patch files - manual edits are saved as diff output in
                'bad<CMS/ROA><filestem>.stageN.patch' (N=0..1)
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
CGTOOLS=$RPKI_ROOT/cg/tools     # Charlie Gardiner's tools

# Options and defaults
OUTPUT_DIR="$RPKI_ROOT/testcases/conformance/raw/root"
PATCHES_DIR="$RPKI_ROOT/testcases/conformance/raw/patches"
ROOT_KEY_PATH="$RPKI_ROOT/testcases/conformance/raw/root.p15"
ROOT_CERT_PATH="$RPKI_ROOT/testcases/conformance/raw/root.cer"
TEMPLATE_EE_RAW="$RPKI_ROOT/testcases/conformance/raw/templates/goodEECert.raw"
TEMPLATE_ROA_RAW="$RPKI_ROOT/testcases/conformance/raw/templates/goodROA.raw"
USE_EXISTING_PATCHES=

# Process command line arguments.
while getopts Pk:o:t:p:h opt
do
  case $opt in
      P)
          USE_EXISTING_PATCHES=1
          ;;
      k)
          ROOT_KEY_PATH=$OPTARG
          ;;
      o)
          OUTPUT_DIR=$OPTARG
          ;;
      p)
          PATCHES_DIR=$OPTARG
          ;;
      h)
          usage
          ;;
  esac
done
shift $((OPTIND - 1))
if [ $# = "3" ]
then
    TEST_CLASS=$1
    FILESTEM=$2
    SERIAL=$3
else
    usage
fi


###############################################################################
# Computed Variables
###############################################################################

child_name=bad${TEST_CLASS}${FILESTEM}
ee_name=bad${TEST_CLASS}EE${FILESTEM}

###############################################################################
# Check for prerequisite tools and files
###############################################################################

ensure_file_exists ( ) {
    if [ ! -e "$1" ]
    then
        echo "Error: file not found - $1" 1>&2
        exit 1
    fi
}

ensure_dir_exists ( ) {
    if [ ! -d "$1" ]
    then
        echo "Error: directory not found - $1" 1>&2
        exit 1
    fi
}

ensure_dir_exists $OUTPUT_DIR
ensure_dir_exists $PATCHES_DIR
ensure_file_exists $ROOT_KEY_PATH
ensure_file_exists $ROOT_CERT_PATH
ensure_file_exists $TEMPLATE_EE_RAW
ensure_file_exists $TEMPLATE_ROA_RAW
ensure_file_exists $CGTOOLS/rr
ensure_file_exists $CGTOOLS/put_sernum
ensure_file_exists $CGTOOLS/put_subj
ensure_file_exists $CGTOOLS/add_key_info
ensure_file_exists $CGTOOLS/dump_smart
ensure_file_exists $CGTOOLS/sign_cert

if [ $USE_EXISTING_PATCHES ]
then
    ensure_file_exists $PATCHES_DIR/${child_name}.stage0.patch
    ensure_file_exists $PATCHES_DIR/${child_name}.stage1.patch
fi

###############################################################################
# Generate Child cert
###############################################################################

cd ${OUTPUT_DIR}

# $1=CMS/ROA/MFT, $2=fault type, $3 =sernum
cp ${TEMPLATE_EE_RAW} ${ee_name}.raw
${CGTOOLS}/rr <${ee_name}.raw >${ee_name}.cer
${CGTOOLS}/put_sernum ${ee_name}.cer ${SERIAL}
${CGTOOLS}/put_subj ${ee_name}.cer ${ee_name}
${CGTOOLS}/gen_key ${ee_name}.p15 2048
${CGTOOLS}/add_key_info ${ee_name}.cer ${ee_name}.p15 ${ROOT_CERT_PATH}
rm ${ee_name}.cer.raw
${CGTOOLS}/dump_smart ${ee_name}.cer >${ee_name}.raw

# Modify EE automatically or manually
if [ $USE_EXISTING_PATCHES ]
then
    patch ${ee_name}.raw ${PATCHES_DIR}/${ee_name}.stage0.patch
else
    cp ${ee_name}.raw ${ee_name}.raw.old
    vi ${ee_name}.raw
    diff -u ${ee_name}.raw.old ${ee_name}.raw \
        >${PATCHES_DIR}/${ee_name}.stage0.patch || true
fi

# Sign EE cert
${CGTOOLS}/rr <${ee_name}.raw >${ee_name}.cer
${CGTOOLS}/sign_cert ${ee_name}.cer ${ROOT_KEY_PATH}

# Make ROA
cp ${TEMPLATE_ROA_RAW} ${child_name}.raw

# Modify ROA's to-be-signed portions automatically or manually
if [ $USE_EXISTING_PATCHES ]
then
    patch ${child_name}.raw ${PATCHES_DIR}/${child_name}.stage1.patch
else
    cp ${child_name}.raw ${child_name}.raw.old
    vi ${child_name}.raw
    diff -u ${child_name}.raw.old ${child_name}.raw \
        >${PATCHES_DIR}/${child_name}.stage1.patch || true
fi

# Embed EE into ROA and sign using EE private key
${CGTOOLS}/rr <${child_name}.raw >${child_name}.roa
${CGTOOLS}/add_cms_cert ${ee_name}.cer ${child_name}.roa \
    ${ee_name}.p15 ${child_name}.roa
${CGTOOLS}/dump_smart ${child_name}.roa > ${child_name}.raw

# Modify ROA's not-signed portions automatically or manually
if [ $USE_EXISTING_PATCHES ]
then
    patch ${child_name}.raw ${PATCHES_DIR}/${child_name}.stage2.patch
else
    cp ${child_name}.raw ${child_name}.raw.old
    vi ${child_name}.raw
    diff -u ${child_name}.raw.old ${child_name}.raw \
        >${PATCHES_DIR}/${child_name}.stage2.patch || true
fi

# Convert back into binary
${CGTOOLS}/rr <${child_name}.raw >${child_name}.roa
