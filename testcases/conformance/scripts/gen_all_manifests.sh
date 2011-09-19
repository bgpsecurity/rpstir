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
#  Contributor(s): Charlie Gardiner, Andrew Chi
#
#  ***** END LICENSE BLOCK ***** */

# gen_all_roas.sh - create all certificates for RPKI syntax
#                    conformance test

# Set up RPKI environment variables if not already done.
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../../../envir.setup

# Safe bash shell scripting practices
. $RPKI_ROOT/trap_errors

# Usage
usage ( ) {
    usagestr="
Usage: $0 [options]

Options:
  -P        \tApply patches instead of prompting user to edit (default = false)
  -h        \tDisplay this help file

This script creates a large number of manifests (with embedded EE certs), 
prompts the user multiple times to edit interactively (e.g., in order 
to introduce errors), and captures those edits in '.patch' files (output 
of diff -u).  Later, running $0 with the -P option can replay the creation
process by automatically applying those patch files instead of
prompting for user intervention.

This tool assumes the repository structure in the diagram below.  It
creates a ton of manifests (with embedded EE certs).  In the EE certs' SIA, the
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

This script creates a number of manifests, prompts the user multiple times 
to edit it interactively (e.g., in order to introduce errors), and captures
those edits in '.patch' files (output of diff -u).  Later,
make_test_imanifest.sh can replay the creation process by automatically
applying those patch files instead of prompting for user intervention.

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
  -P - (optional) use patch mode for automatic insertion of errors

Outputs:
  ROA - AS/IP is hardcoded in goodCert.raw and goodROA templates
  patch files - manual edits are saved as diff output in
                'badi<CMS><filestem>.stageN.patch' (N=0..1) in the patch
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

single_CMS_script="$RPKI_ROOT/testcases/conformance/scripts/make_test_CMS.sh"
single_CMS_cmd="${single_CMS_script} ${patch_option} -o ${OUTPUT_DIR}"

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
ensure_file_exists "${single_CMS_script}"

###############################################################################
# Generate CMS cases
###############################################################################

${single_CMS_cmd} 512 ContentType              # wrong content type
${single_CMS_cmd} 513 NoCerts                  # no certificate
${single_CMS_cmd} 514 2Certs                   # two certificates
${single_CMS_cmd} 515 Version2                 # version 2
${single_CMS_cmd} 516 Version4                 # version 4
${single_CMS_cmd} 517 DigestAlg                # wrong digest algorithm
${single_CMS_cmd} 518 2DigestAlgs              # two digest algorithms
${single_CMS_cmd} 519 NoDigestAlgs             # no digest algorithm
${single_CMS_cmd} 520 HasCRL                   # has a CRL
${single_CMS_cmd} 522 NoSignerInfo             # no SignerInfo field
${single_CMS_cmd} 523 SigInfoVersion           # wrong Signer Info version -- 2
${single_CMS_cmd} 524 SigInfoVersion4          # wrong Signer Info version -- 4
${single_CMS_cmd} 525 SigInfoNoSid             # no Signer Identifier
${single_CMS_cmd} 526 SigInfoWrongSid          # wrong Signer Identifier
${single_CMS_cmd} 527 SigInfoBadSid            # wrong choice of Signer Identifier
${single_CMS_cmd} 528 SigInfoHashAlg           # wrong hash algorithm in Signer Info
${single_CMS_cmd} 529 SigInfoNoAttrs           # no attributes in Signer Info
${single_CMS_cmd} 530 SigInfoAttrsNoContType   # no content type in Signer Info
${single_CMS_cmd} 531 SigInfoAttrsContTypeOid  # wrong content type OID
${single_CMS_cmd} 532 SigInfoAttrsMsgDigestOid # wrong digest OID attribute
${single_CMS_cmd} 533 SigInfoAttrsNoMsgDigest  # no message digest
${single_CMS_cmd} 534 SigInfoAttrs2ContType    # duplicate content type attributes
${single_CMS_cmd} 535 SigInfoAttrs2MsgDigest   # duplicate digest attributes
${single_CMS_cmd} 536 SigInfoAttrs2SigTime     # duplicate signng time attributes
${single_CMS_cmd} 537 SigInfoAttrs2BinSigTime  # duplicate binary signing time attributes
${single_CMS_cmd} 538 SigInfoUnSigAttrs        # has unsigned attribute
${single_CMS_cmd} 539 SigInfoNoSig             # no signature
${single_CMS_cmd} 540 SigInfo2Sig              # has two signatures
${single_CMS_cmd} 541 SigInfoNoSigAlg          # has no signature algorithm
${single_CMS_cmd} 542 SigInfoNoHashAlg         # had no hash algorithm

