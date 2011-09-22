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

This script creates a large number of ROAs (with embedded EE certs),
prompts the user multiple times to edit interactively (e.g., in order
to introduce errors), and captures those edits in '.patch' files
(output of diff -u).  Later, running $0 with the -P option can replay
the creation process by automatically applying those patch files
instead of prompting for user intervention.  In patch mode, existing
keys are reused from the keys directory, instead of the default of
generating new keys.

This tool assumes the repository structure in the diagram below.  It
creates a ton of ROAs (with embedded EE certs).  In the EE certs' SIA, the
accessMethod id-ad-signedObject will have an accessLocation of
rsync://rpki.bbn.com/conformance/root/subjname.roa.

NOTE: this script does NOT update the manifest issued by root.

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
  -P - (optional) use patch mode for automatic insertion of errors

Outputs:
  ROA - AS/IP is hardcoded in goodCert.raw and goodROA templates
  patch files - manual edits are saved as diff output in
                'badCMS<filestem>.stageN.patch' (N=0..1) in the patch
                directory
  key files - generated key pairs for the EE certs are stored in keys directory
              as badCMS<filestem>.ee.p15
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

${single_CMS_cmd} CMS 512 ContentType              
${single_CMS_cmd} CMS 513 NoCerts                  
${single_CMS_cmd} CMS 514 2Certs                   
${single_CMS_cmd} CMS 515 Version2                 
${single_CMS_cmd} CMS 516 Version4                 
${single_CMS_cmd} CMS 517 DigestAlg                
${single_CMS_cmd} CMS 518 2DigestAlgs              
${single_CMS_cmd} CMS 519 NoDigestAlgs             
${single_CMS_cmd} CMS 520 HasCRL                   
${single_CMS_cmd} CMS 522 NoSignerInfo             
${single_CMS_cmd} CMS 523 SigInfoVersion           
${single_CMS_cmd} CMS 524 SigInfoVersion4          
${single_CMS_cmd} CMS 525 SigInfoNoSid             
${single_CMS_cmd} CMS 526 SigInfoWrongSid          
${single_CMS_cmd} CMS 527 SigInfoBadSid            
${single_CMS_cmd} CMS 528 SigInfoHashAlg           
${single_CMS_cmd} CMS 529 SigInfoNoAttrs           
${single_CMS_cmd} CMS 530 SigInfoAttrsNoContType   
${single_CMS_cmd} CMS 531 SigInfoAttrsContTypeOid  
${single_CMS_cmd} CMS 532 SigInfoAttrsMsgDigestOid 
${single_CMS_cmd} CMS 533 SigInfoAttrsNoMsgDigest  
${single_CMS_cmd} CMS 534 SigInfoAttrs2ContType    
${single_CMS_cmd} CMS 535 SigInfoAttrs2MsgDigest   
${single_CMS_cmd} CMS 536 SigInfoAttrs2SigTime     
${single_CMS_cmd} CMS 537 SigInfoAttrs2BinSigTime  
${single_CMS_cmd} CMS 538 SigInfoUnSigAttrs        
${single_CMS_cmd} CMS 539 SigInfoNoSig             
${single_CMS_cmd} CMS 540 SigInfo2Sig              
${single_CMS_cmd} CMS 541 SigInfoNoSigAlg          
${single_CMS_cmd} CMS 542 SigInfoNoHashAlg         
