#!/bin/bash
#

# make_test_cert.sh - manually create certificate for RPKI syntax
#                     conformance test

# This script creates a certificate, prompts the user multiple times
# to interactively edit (e.g., in order to introduce errors), and
# captures those edits in ".patch" files (output of diff -u).  Later,
# make_test_cert.sh with the -P option can replay the creation process
# by automatically applying those patch files without user
# intervention.

# Set up RPKI environment variables if not already done.
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../../../envir.setup

# Safe bash shell scripting practices
. $RPKI_ROOT/trap_errors

# Usage
usage ( ) {
    usagestr="
Usage: $0 [options] <serial> <filestem>

Options:
  -P        \tApply patches instead of prompting user to edit (default = false)
  -k keyfile\tRoot's key (default = ...conformance/raw/root.p15)
  -o outdir \tOutput directory (default = .../conformance/raw/root/)
  -t template\tTemplate cert (default = ...conformance/raw/templates/goodCert.raw)
  -p patchdir\tDirectory for saving/getting patches (default = .../conformance/raw/patches/)
  -h        \tDisplay this help file

This script creates a certificate, prompts the user multiple times to
interactively edit (e.g., in order to introduce errors), and captures
those edits in '.patch' files (output of diff -u).  Later, running $0
with the -P option can replay the creation process by automatically
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
  -P - (optional) use patch mode for automatic insertion of errors
  keyfile - (optional) local path to root key pair
  outdir - (optional) local path to root's repo directory
  patchdir - (optional) local path to directory of patches
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
OUTPUT_DIR="$RPKI_ROOT/testcases/conformance/raw/root"
PATCHES_DIR="$RPKI_ROOT/testcases/conformance/raw/patches"
ROOT_KEY_PATH="$RPKI_ROOT/testcases/conformance/raw/root.p15"
TEMPLATE_CERT_RAW="$RPKI_ROOT/testcases/conformance/raw/templates/goodCert.raw"
USE_EXISTING_PATCHES=
EDITOR=${EDITOR:-vi}		# set editor to vi if undefined

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
      t)
	  TEMPLATE_CERT_RAW=$OPTARG
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
if [ $# = "2" ]
then
    SERIAL=$1
    FILESTEM=$2
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
ensure_file_exists $TEMPLATE_CERT_RAW
ensure_file_exists $CGTOOLS/rr
ensure_file_exists $CGTOOLS/put_sernum
ensure_file_exists $CGTOOLS/put_subj
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

# Customize w/ serial number and subject name (based on $child_name)
cp ${TEMPLATE_CERT_RAW} ${child_name}.raw
${CGTOOLS}/rr <${child_name}.raw >${child_name}.cer
${CGTOOLS}/put_sernum ${child_name}.cer ${SERIAL}
${CGTOOLS}/put_subj ${child_name}.cer ${child_name}
${CGTOOLS}/dump_smart ${child_name}.cer >${child_name}.raw

# Pre-signing modification: manual or automatic (can be no-op)
if [ $USE_EXISTING_PATCHES ]
then
    patch ${child_name}.raw ${PATCHES_DIR}/${child_name}.stage0.patch
else
    cp ${child_name}.raw ${child_name}.raw.old
    ${EDITOR} ${child_name}.raw
    diff -u ${child_name}.raw.old ${child_name}.raw \
	>${PATCHES_DIR}/${child_name}.stage0.patch || true
fi

# Sign it
${CGTOOLS}/rr <${child_name}.raw >${child_name}.blb
${CGTOOLS}/sign_cert ${child_name}.blb ${ROOT_KEY_PATH}
mv ${child_name}.blb ${child_name}.cer
${CGTOOLS}/dump_smart ${child_name}.cer >${child_name}.raw

# Post-signing modification: manual or automatic (can be no-op)
if [ $USE_EXISTING_PATCHES ]
then
    patch ${child_name}.raw ${PATCHES_DIR}/${child_name}.stage1.patch
else
    cp ${child_name}.raw ${child_name}.raw.old
    ${EDITOR} ${child_name}.raw
    diff -u ${child_name}.raw.old ${child_name}.raw \
	>${PATCHES_DIR}/${child_name}.stage1.patch || true
fi

# Convert back into DER-encoded binary.
${CGTOOLS}/rr <${child_name}.raw >${child_name}.cer

# Clean-up
rm ${child_name}.raw
if [ ! $USE_EXISTING_PATCHES ]
then
    rm ${child_name}.raw.old
fi

# Notify user of output locations
echo Successfully created "${OUTPUT_DIR}/${child_name}.cer"
if [ ! $USE_EXISTING_PATCHES ]
then
    echo Successfully created "${PATCHES_DIR}/${child_name}.stage0.patch"
    echo Successfully created "${PATCHES_DIR}/${child_name}.stage1.patch"
fi
