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

# make_test_cert.sh - manually create RPKI syntax conformance test certificate

# This script creates a certificate, prompts the user multiple times
# to interactively edit (e.g., in order to introduce errors), and
# captures those edits in ".patch" files (output of diff -u).  Later,
# patch_test_cert.sh can replay the creation process by automatically
# applying those patch files without user intervention.

# Set up RPKI environment variables if not already done.
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../../../envir.setup

# Usage
usage ( ) {
    usagestr="
Usage: $0 [options] <filestem> <serial>

Options:
  -k keyfile\tPath to root's key pair (default: ../raw/root.p15)
  -h        \tDisplay this help file

This script creates a certificate, prompts the user multiple times to
interactively edit (e.g., in order to introduce errors), and captures
those edits in '.patch' files (output of diff -u).  Later,
patch_test_cert.sh can replay the creation process by automatically
applying those patch files instead of prompting for user intervention.

This tool assumes the repository structure in the diagram below.  It
creates only the certificate labeled 'Child'.


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
               +-------------------------------------------------+
               | rsync://rpki.bbn.com/conformance/root/goodCert/ |
               |                                                 |
               | Empty Directory (MFT intentionally omitted)     |
               +-------------------------------------------------+

Inputs:
  filestem - subject name (and filename stem) for 'Child' to be created
  serial - serial number for 'Child' to be created
  keyfile - (optional) local path to root key pair

Outputs:
  child CA certificate - AS/IP resources are hardcoded in goodCert.raw template
    "
    printf "${usagestr}\n"
    exit 1
}

cp goodCert.raw badCert$1.raw
rr <badCert$1.raw >badCert$1.cer
put_sernum badCert$1.cer $2
dump_smart badCert$1.cer >badCert$1.raw
#
cp badCert$1.raw badCert$1.raw.old
vi badCert$1.raw
diff -u badCert$1.raw.old badCert$1.raw >badCert$1.stage0.patch
#
rr <badCert$1.raw >badCert$1.blb
sign_cert badCert$1.blb ../root.p15
mv badCert$1.blb badCert$1.cer
dump_smart badCert$1.cer >badCert$1.raw
#
cp badCert$1.raw badCert$1.raw.old
vi badCert$1.raw
diff -u badCert$1.raw.old badCert$1.raw >badCert$1.stage1.patch
rr <badCert$1.raw >badCert$1.cer
