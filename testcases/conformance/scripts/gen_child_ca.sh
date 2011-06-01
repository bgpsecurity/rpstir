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
Usage: $0 [options] <subjectname> <serial> <parentcertfile> <parentURI> <parentkeyfile> <crldp>

Options:
  -b crl|mft\tChild CRL or manifest should be named 'bad<subjectname>.*'
  -o outdir\tOutput directory (default = CWD)
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

Outputs:
  child CA certificate - inherits AS/IP resources from parent via inherit bit
  child key pair - not shown in diagram, <outdir>/<subjectname>.p15
  child repo directory - ASSUMED to be a subdirectory of parent's repo. The
                         new directory will be <outdir>/<subjectname>/
  crl issued by child - named <subjectname>.crl, and has no entries
  mft issued by child - named <subjectname>.mft, and has one entry (the crl)

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
#CHILDCERT_TEMPLATE="$RPKI_ROOT/testbed/templates/ca_template.cer"
CHILDCRL_TEMPLATE="$RPKI_ROOT/testbed/templates/crl_template.crl"
CHILDMFT_TEMPALTE="$RPKI_ROOT/testbed/templates/mft_tempalte.mft"

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

# Extract SIA directory from parent (rsync URI)
parent_sia=$($CGTOOLS/extractSIA $PARENT_CERT_FILE)
check_errs $? "Failed to extract SIA"

# Compute SIA directory (rsync URI) for child CA
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

# Compute SIA manifest (rsync URI) for child CA
child_sia_mft="${child_sia_dir}${child_mft_name}"

# Create child cert
# 1. Generate child key pair
child_key_file=${OUTPUT_DIR}/${SUBJECTNAME}.p15
$CGTOOLS/gen_key $child_key_file 2048
check_errs $? "Failed to generate key pair $child_key_file"

# 2. Create/sign child certificate with appropriate parameters
childcert_template=$PARENT_CERT_FILE  # get default field values from parent
if [ ! -e ${childcert_template} ]
then
    printf "Error - file not found: template cert ${childcert_template}\n"
    exit 1
fi
child_cert_file=${OUTPUT_DIR}/${SUBJECTNAME}.cer
$TBTOOLS/create_object -t ${childcert_template} CERT \
    parentcertfile=${PARENT_CERT_FILE} \
    parentkeyfile=${PARENT_KEY_FILE} \
    subjkeyfile=${child_key_file} \
    type=CA \
    notbefore=100101000000Z \
    notafter=20800101000000Z \
    serial=${SERIAL} \
    subject=${SUBJECTNAME} \
    crldp=${CRLDP} \
    aia=${PARENT_URI} \
    sia="r:${child_sia_dir},m:${child_sia_mft}" \
    ipv4=inherit \
    ipv6=inherit \
    as=inherit \
    outputfilename=${child_cert_file}
check_errs $? "Failed to create child certificate: ${child_cert_file}"

# Create child publication directory
child_sia_path=${OUTPUT_DIR}/${SUBJECTNAME}
mkdir -p $child_sia_path
check_errs $? "Failed to create child SIA directory: $child_sia_path"

# Create child CRL


# Create child Manifest
