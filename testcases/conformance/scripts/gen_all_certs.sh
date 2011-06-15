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

# gen_all_certs.sh - create all certificates for RPKI syntax
#                    conformance test

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
Usage: $0 [options]

Options:
  -P        \tApply patches instead of prompting user to edit (default = false)
  -h        \tDisplay this help file

This script creates a large number of certificates, and for each one
prompts the user multiple times to interactively edit (e.g., in order
to introduce errors), and captures those edits in '.patch' files
(output of diff -u).  Later, running $0 with the -P option can replay
the creation process by automatically applying those patch files
instead of prompting for user intervention.

This tool assumes the repository structure in the diagram below.  It
creates a ton of certificates in the position of the certificate
labeled 'Child'.  In the Child's SIA, the accessMethod
id-ad-rpkiManifest will have an accessLocation of
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
  -P - (optional) use patch mode for automatic insertion of errors

Outputs:
  child CA certificates - AS/IP is hardcoded in goodCert.raw template
  patch files - manual edits are saved as diff output in
                'badCert<filestem>.stageN.patch' (N=0..1) in the patch
                directory
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
USE_EXISTING_PATCHES=

# Process command line arguments.
while getopts Ph opt
do
  case $opt in
      P)
	  USE_EXISTING_PATCHES=1
	  ;;
      h)
	  usage
	  ;;
  esac
done
shift $((OPTIND - 1))
if [ $# != "0" ]
then
    usage
fi

###############################################################################
# Computed Variables
###############################################################################

if [ $USE_EXISTING_PATCHES ]
then
    patch_option="-P"
else
    patch_option=
fi

single_cert_script="$RPKI_ROOT/testcases/conformance/scripts/make_test_cert.sh"
single_cert_cmd="${single_cert_script} ${patch_option} -o ${OUTPUT_DIR}"

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

ensure_dir_exists "$OUTPUT_DIR"
ensure_dir_exists "$CGTOOLS"
ensure_file_exists "${single_cert_script}"

###############################################################################
# Generate Child certificates
###############################################################################

${single_cert_cmd} AIA2AccessDesc 101
${single_cert_cmd} AIABadAccess 102
${single_cert_cmd} AIAAccessLoc 103
${single_cert_cmd} AIACrit 104
${single_cert_cmd} AKIHash 105
${single_cert_cmd} AKILth 106
${single_cert_cmd} BadExtension1 107
${single_cert_cmd} BasicConstrNoCA 109
${single_cert_cmd} BasicConstrNoCrit 110
${single_cert_cmd} BasicConstrPathLth 111
${single_cert_cmd} Cpol2oid 112
${single_cert_cmd} CpolNoCrit 113
${single_cert_cmd} CRLDP2DistPt 114
${single_cert_cmd} CRLDPCrit 115
${single_cert_cmd} CRLDPCrlIssuer 116
${single_cert_cmd} CRLDPNoDistPt 117
${single_cert_cmd} CRLDPReasons 118
${single_cert_cmd} EKU 119
${single_cert_cmd} InnerSigAlg 120
${single_cert_cmd} IssuerOID 121
${single_cert_cmd} Issuer2Sets 122
${single_cert_cmd} IssuerUtf 123
${single_cert_cmd} Issuer2Seq 124
${single_cert_cmd} Issuer2SerNums 125
${single_cert_cmd} IssUID 126
${single_cert_cmd} KUsageExtra 127
${single_cert_cmd} KUsageNoCertSign 128
${single_cert_cmd} KUsageNoCrit 129
${single_cert_cmd} KUsageNoCRLSign 131
${single_cert_cmd} OuterSigAlg 134
${single_cert_cmd} PubKeyAlg 135
${single_cert_cmd} PubKeyExp 136
${single_cert_cmd} PubKeyLth 137
${single_cert_cmd} ResourcesASNoCrit 138
${single_cert_cmd} ResourcesBadAFI 139
${single_cert_cmd} ResourcesBadASOrder 140
${single_cert_cmd} ResourcesBadV4Order 141
${single_cert_cmd} ResourcesBadV6Order 142
${single_cert_cmd} ResourcesIPNoCrit 143
${single_cert_cmd} ResourcesNone 144
${single_cert_cmd} ResourcesSAFI 145
${single_cert_cmd} SIAAccessLoc 147
${single_cert_cmd} SIAAccessMethod 148
${single_cert_cmd} SIAMissing 149
${single_cert_cmd} SKIHash 150
${single_cert_cmd} SKILth 151
${single_cert_cmd} SubjectOID 152
${single_cert_cmd} Subject2Sets 153
${single_cert_cmd} SubjectUtf 154
${single_cert_cmd} Subject2Seq 155
${single_cert_cmd} Subject2SerNum 156
${single_cert_cmd} SubjUID 157
${single_cert_cmd} ValCrossed 158
${single_cert_cmd} ValFromFuture 159
${single_cert_cmd} ValFromTyp 160
${single_cert_cmd} ValToPast 162
${single_cert_cmd} ValToTyp 163
${single_cert_cmd} VersionNeg 164
${single_cert_cmd} Version1 165
${single_cert_cmd} Version2 166
${single_cert_cmd} Version4 167
${single_cert_cmd} SerNum 168
${single_cert_cmd} AIA2x 169
${single_cert_cmd} SIA2x 170
${single_cert_cmd} NoAIA 171
${single_cert_cmd} NoSIA 172
${single_cert_cmd} NoBasicConstr 173
${single_cert_cmd} 2BasicConstr 174
${single_cert_cmd} NoSKI 175
${single_cert_cmd} 2SKI 176
${single_cert_cmd} NoAKI 177
${single_cert_cmd} 2AKI 178
${single_cert_cmd} NoKeyUsage 179
${single_cert_cmd} 2KeyUsage 180
${single_cert_cmd} 2CRLDP 181
${single_cert_cmd} NoCRLDP 182
${single_cert_cmd} NoCpol 183
${single_cert_cmd} 2Cpol 184
${single_cert_cmd} 2IPAddr 185
${single_cert_cmd} 2ASNum 186
