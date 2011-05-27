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



# Set up environment variables if not already done.
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../../../envir.setup

# Set up paths to ASN.1 tools.
CGTOOLS=$RPKI_ROOT/cg/tools	# Charlie Gardiner's tools
TBTOOLS=$RPKI_ROOT/testbed/src	# Tools used for testbed generation

# Usage
usage ( ) {
    usagestr="
Usage: $0 [options] <subjectname> <serial> <parentcertfile> <parentkeyfile>

Options:
  -b crl|mft\tchild CRL or manifest will be named 'bad<subjectname>.*'
  -o outdir\tOutput directory (default = PWD)

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
  parentcertfile - path to parent certificate file
  parentkeyfile - path to parent key pair (.p15 file)
  subjectname - subject name for the child
  serial - serial number for the child
  outdir - path to parent's repo directory.  Defaults to PWD
  crldp - full rsync URI to 'CRL issued by Parent'.  Defaults to
          <parentSIA>/<parentSubjectName>.crl

Outputs:
  child CA certificate - verifiable in the usual fashion by the parent pubkey
  child key pair - not shown in diagram, <outdir>/<subjectname>.p15
  child repo directory - ASSUMED to be a subdirectory of parent's repo and
                         named by the child's subjectname
  crl issued by child - named <subjectname>.crl, and left empty
  mft issued by child - named <subjectname>.mft, includes one item (the crl)

  For convenience in generating the RPKI conformance test cases, the
  caller may optionally specify that the filename for either the crl
  or mft should be prepended by the string 'bad'.
    "
    printf "${usagestr}\n"
    exit 1
}

# Options and defaults
MAKE_CRL_BAD=0
MAKE_MFT_BAD=0
OUTPUT_DIR="."
CHILDCERT_RAW_TEMPLATE="$RPKI_ROOT/testcases/conformance/raw/root/goodCert.raw"
CHILDCERT_TEMPLATE="$RPKI_ROOT/testcases/conformance/raw/root/goodCert.cer"

# Process command line arguments.
while getopts b:o:h opt
do
  case $opt in
      b)
      	  if [ $OPTARG = "crl" ]
	  then
	      MAKE_CRL_BAD=1
	  elif [ $OPTARG = "mft" ]
	  then
	      MAKE_MFT_BAD=1
	  else
	      usage
	  fi
	  ;;
      o)
	  OUTPUT_DIR=$OPTARG
	  ;;
      h)
	  usage
	  ;;
  esac
done
shift $((OPTIND - 1))
if [ $# = "4" ]
then
    SUBJECTNAME=$1
    SERIAL=$2
    PARENT_CERT_FILE=$3
    PARENT_KEY_FILE=$4
else
    usage
fi

# Extract SIA directory from parent
parent_sia=$($CGTOOLS/extractSIA $PARENT_CERT_FILE)
check_errs $? "Failed to extract SIA"

# Compute SIA directory URI for child CA
child_sia_dir="${parent_sia}${SUBJECTNAME}/"

# Compute manifest name for child CA
if [ $MAKE_MFT_BAD = "1" ]
then
    child_mft_name="bad${SUBJECTNAME}.mft"
else
    child_mft_name="${SUBJECTNAME}.mft"
fi

# Compute CRL name for child CA
if [ $MAKE_CRL_BAD = "1" ]
then
    child_crl_name="bad${SUBJECTNAME}.crl"
else
    child_crl_name="${SUBJECTNAME}.crl"
fi

# Compute SIA manifest URI for child CA
child_sia_mft="${child_sia_dir}${child_mft_name}"

# Create child cert
# 1. Generate child key pair
child_key_file=${OUTPUT_DIR}/${SUBJECTNAME}.p15
$CGTOOLS/gen_key $childkeyfile 2048
check_errs $? "Failed to generate key pair $child_key_file"

# 2. Create/sign child certificate with appropriate parameters

# Create child publication directory

# Create child CRL

# Create child Manifest
