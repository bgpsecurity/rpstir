#!/bin/bash
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
#  Contributor(s): Andrew Chi
#
#  ***** END LICENSE BLOCK ***** */

# Set up RPKI environment variables if not already done.
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../../../envir.setup

# Safe bash shell scripting practices - exit w/ failure on any error
. $RPKI_ROOT/trap_errors

# Usage
usage ( ) {
    usagestr="
Usage: $0 [options] <subjectname> <serial> <parentcertfile> <parentURI> <parentkeyfile> <crldp>

Options:
  -b crl|mft\tChild CRL or manifest should be named '<prefix><subjectname>.*'
  -x prefix\tPrefix (default = 'bad')
  -o outdir\tOutput directory (default = CWD)
  -d keydir\tKeys directory (default = CWD)
  -h       \tDisplay this help file

This tool takes as input a parent CA certificate + key pair, and as
output, issues a child CA certificate with a minimal publication
subdirectory.  The diagram below shows outputs of the script.  The
inputs and non-participants are indicated by normal boxes; the outputs
are indicated by boxes whose label has a prepended asterisk (*).
Note: this script does NOT update the 'Manifest issued by Parent'.

                    +--------+
         +--------->| Parent |
         |          |  AIA   |
         |  +--------- SIA   |
         |  |       +--------+
         |  |
         |  |  +--------------------------------------+
         |  |  |                                      |
         |  +->|   +--------+     +------------+      |
         |     |   | *Child |     | CRL issued |      |
         |     |   | CRLDP------->| by Parent  |      |
         +----------- AIA   |     +------------+      |
               |   |  SIA------+                      |
               |   +--------+  |  +-----------------+ |
               |               |  | Manifest issued | |
               | Parent's Repo |  | by Parent       | |
               | Directory     |  +-----------------+ |
               +---------------|----------------------+
                               |
                               V
		 +--------------------------------+
     	       	 | +---------------------------+  |
		 | | *Manifest issued by Child |  |
		 | +---------------------------+  |
		 |                                |
		 | +---------------------------+  |
		 | | *CRL issued by Child      |  |
		 | +---------------------------+  |
		 |                                |
		 | *Child's Repo Directory        |
	       	 +--------------------------------+

Inputs:
  subjectname - subject name for the child
  serial - serial number for the child
  parentcertfile - local path to parent certificate file
  parentURI - full rsync URI to parent certificate file
  parentkeyfile - local path to parent key pair (.p15 file)
  crldp - full rsync URI to 'CRL issued by Parent'.  Probably something like
          <parentSIA>/<parentSubjectName>.crl
  outdir - (optional) local path to parent's repo directory.  Defaults to CWD
  keydir - (optional) local path to key directory.  Defaults to CWD.

Outputs:
  child CA certificate - inherits AS/IP resources from parent via inherit bit
  child repo directory - ASSUMED to be a subdirectory of parent's repo. The
                         new directory will be <outdir>/<subjectname>/
  crl issued by child - named <subjectname>.crl, and has no entries
  mft issued by child - named <subjectname>.mft, and has one entry (the crl)

  For convenience in generating the RPKI conformance test cases, the
  caller may optionally specify that the filename for either the crl
  or mft should be prepended by the string 'bad'.

Auxiliary Outputs: (not shown in diagram)
  child key pair - <keydir>/<subjectname>.p15
  child-issued MFT EE cert - <outdir>/<subjectname>/<subjectname>.mft.cer
  child-issued MFT EE key pair - <keydir>/<subjectname>.mft.p15
    "
    printf "${usagestr}\n"
    exit 1
}

# NOTES
# 1. Variable naming convention -- preset constants and command line
# arguments are in ALL_CAPS.  Derived/computed values are in
# lower_case.
# 2. Dependencies: This script assumes the existence (and PATH
# accessibility) of the standard tools 'sed' and 'sha256sum'.

# Set up paths to ASN.1 tools.
CGTOOLS=$RPKI_ROOT/cg/tools	# Charlie Gardiner's tools
TBTOOLS=$RPKI_ROOT/testbed/src	# Tools used for testbed generation

# Options and defaults
USE_CRL_PREFIX=0
USE_MFT_PREFIX=0
PREFIX="bad"
OUTPUT_DIR="."
KEYS_DIR="."
USE_EXISTING_KEYS=
CACERT_TEMPLATE="$RPKI_ROOT/testbed/templates/ca_template.cer"
EECERT_TEMPLATE="$RPKI_ROOT/testbed/templates/ee_template.cer"
CRL_TEMPLATE="$RPKI_ROOT/testbed/templates/crl_template.crl"
MFT_TEMPLATE="$RPKI_ROOT/testbed/templates/M.man"

# Process command line arguments.
while getopts b:o:x:d:Kh opt
do
  case $opt in
      b)
      	  if [ $OPTARG = "crl" ]
	  then
	      USE_CRL_PREFIX=1
	  elif [ $OPTARG = "mft" ]
	  then
	      USE_MFT_PREFIX=1
	  else
	      usage
	  fi
	  ;;
      o)
	  OUTPUT_DIR=$OPTARG
	  ;;
      x)
          PREFIX=$OPTARG
          ;;
      d)
          KEYS_DIR=$OPTARG
          ;;
      K)
          USE_EXISTING_KEYS=1
          ;;
      h)
	  usage
	  ;;
  esac
done
shift $((OPTIND - 1))
if [ $# = "6" ] 
then
    SUBJECTNAME=$1
    SERIAL=$2
    PARENT_CERT_FILE=$3
    PARENT_URI=$4
    PARENT_KEY_FILE=$5
    CRLDP=$6
else
    usage
fi

###############################################################################
# Check for prerequisite tools
###############################################################################

# Ensure executables are in PATH
hash sha256sum
hash sed

ensure_file_exists $CGTOOLS/extractSIA
ensure_file_exists $CGTOOLS/extractValidityDate
ensure_file_exists $CGTOOLS/gen_key
ensure_file_exists $TBTOOLS/create_object

###############################################################################
# Compute Paths (both rsync URIs and local paths)
###############################################################################

# Extract SIA directory from parent (rsync URI)
parent_sia=$($CGTOOLS/extractSIA $PARENT_CERT_FILE)
echo "Parent SIA: ${parent_sia}"

# Extract validity dates from parent in both X.509 (utctime or gmtime,
# depending on the date) and MFT (gmtime) formats.
parent_notbefore=$($CGTOOLS/extractValidityDate -b $PARENT_CERT_FILE)
parent_notafter=$($CGTOOLS/extractValidityDate -a $PARENT_CERT_FILE)
parent_notbefore_gtime=$($CGTOOLS/extractValidityDate -b -g $PARENT_CERT_FILE)
parent_notafter_gtime=$($CGTOOLS/extractValidityDate -a -g $PARENT_CERT_FILE)

# Compute SIA directory (rsync URI) for child CA
child_sia_dir="${parent_sia}${SUBJECTNAME}/"

# Compute manifest name for child CA
if [ $USE_MFT_PREFIX = "1" ]
then
    child_mft_name="${PREFIX}${SUBJECTNAME}.mft"
else
    child_mft_name="${SUBJECTNAME}.mft"
fi

# Compute CRL name for child CA
if [ $USE_CRL_PREFIX = "1" ]
then
    child_crl_name="${PREFIX}${SUBJECTNAME}.crl"
else
    child_crl_name="${SUBJECTNAME}.crl"
fi

# Compute SIA manifest (rsync URI) for child CA
child_sia_mft="${child_sia_dir}${child_mft_name}"

# Compute CRLDP for grandchildren (i.e. child CA's children)
grandchildren_crldp="${child_sia_dir}${child_crl_name}"

# Compute AIA for grandchildren (i.e. child CA's children)
grandchildren_aia="${parent_sia}${SUBJECTNAME}.cer"

# Compute local paths to child CA
child_cert_path=${OUTPUT_DIR}/${SUBJECTNAME}.cer
 
# Compute local paths to child CA publication point and CRL/manifest
child_sia_path=${OUTPUT_DIR}/${SUBJECTNAME}
child_crl_path=${child_sia_path}/${child_crl_name}
child_mft_path=${child_sia_path}/${child_mft_name}
child_mft_ee_path=${child_sia_path}/${child_mft_name}.cer

# Compute paths to keys
child_key_path=${KEYS_DIR}/${SUBJECTNAME}.p15
child_mft_ee_key_path=${KEYS_DIR}/${child_mft_name}.p15

###############################################################################
# Check for prerequisite files
###############################################################################

ensure_dir_exists $OUTPUT_DIR
ensure_file_exists ${PARENT_CERT_FILE}
ensure_file_exists ${PARENT_KEY_FILE}
ensure_file_exists ${CACERT_TEMPLATE}
ensure_file_exists ${EECERT_TEMPLATE}
if [ ${USE_EXISTING_KEYS} ]
then
    ensure_file_exists $child_key_path
    ensure_file_exists $child_mft_ee_key_path
fi

###############################################################################
# Generate child cert
###############################################################################

# Create child cert
# 1. Generate child key pair
if [ ${USE_EXISTING_KEYS} ]
then
    echo "Using existing key pair: $child_key_path"
else
    $CGTOOLS/gen_key $child_key_path 2048
    echo "Generated key pair: $child_key_path"
fi

# 2. Create/sign child certificate with appropriate parameters
$TBTOOLS/create_object -t ${CACERT_TEMPLATE} CERT \
    outputfilename=${child_cert_path} \
    parentcertfile=${PARENT_CERT_FILE} \
    parentkeyfile=${PARENT_KEY_FILE} \
    subjkeyfile=${child_key_path} \
    type=CA \
    notbefore=${parent_notbefore} \
    notafter=${parent_notafter} \
    serial=${SERIAL} \
    subject=${SUBJECTNAME} \
    crldp=${CRLDP} \
    aia=${PARENT_URI} \
    sia="r:${child_sia_dir},m:${child_sia_mft}" \
    ipv4=inherit \
    ipv6=inherit \
    as=inherit
echo "Created child certificate: ${child_cert_path}"

###############################################################################
# Generate child cert's publication directory
###############################################################################

# Create child publication directory
mkdir -p $child_sia_path
echo "Created child SIA directory: $child_sia_path"

# Create child-issued CRL
$TBTOOLS/create_object -t ${CRL_TEMPLATE} CRL \
    outputfilename=${child_crl_path} \
    parentcertfile=${child_cert_path} \
    parentkeyfile=${child_key_path} \
    thisupdate=${parent_notbefore} \
    nextupdate=${parent_notafter} \
    revokedcertlist= \
    crlnum=1
echo "Created child-issued CRL: ${child_crl_path}"

# Create child-issued Manifest
# 1. Generate EE key pair
if [ ${USE_EXISTING_KEYS} ]
then
    echo "Using existing MFT EE key pair: $child_mft_ee_key_path"
else
    $CGTOOLS/gen_key $child_mft_ee_key_path 2048
    echo "Generated MFT EE key pair: $child_mft_ee_key_path"
fi

# 2. Create child-issued EE cert (to be embedded in the manifest)
$TBTOOLS/create_object -t ${EECERT_TEMPLATE} CERT \
    outputfilename=${child_mft_ee_path} \
    parentcertfile=${child_cert_path} \
    parentkeyfile=${child_key_path} \
    subjkeyfile=${child_mft_ee_key_path} \
    type=EE \
    notbefore=${parent_notbefore} \
    notafter=${parent_notafter} \
    serial=1 \
    subject="${SUBJECTNAME}-mft-ee" \
    crldp=${grandchildren_crldp} \
    aia=${grandchildren_aia} \
    sia="s:${child_sia_mft}" \
    ipv4=inherit \
    ipv6=inherit \
    as=inherit
echo "Created child-issued MFT EE certificate: ${child_mft_ee_path}"

# 3. Compute hash of CRL
child_crl_hash=$(sha256sum ${child_crl_path} | \
    sed -e 's/ .*$//' -e 'y/abcdef/ABCDEF/')
echo "Hash of ${child_crl_name}: 0x${child_crl_hash}"

# 4. Create child-issued Manifest
$TBTOOLS/create_object -t ${MFT_TEMPLATE} MANIFEST \
    outputfilename=${child_mft_path} \
    EECertLocation=${child_mft_ee_path} \
    EEKeyLocation=${child_mft_ee_key_path} \
    thisUpdate=${parent_notbefore_gtime} \
    nextUpdate=${parent_notafter_gtime} \
    manNum=1 \
    filelist=${child_crl_name}'%0x'${child_crl_hash}
echo "Created child-issued MFT: ${child_mft_path}"
