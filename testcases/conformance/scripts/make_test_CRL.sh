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
#  Contributor(s): Charlie Gardiner
#
#  ***** END LICENSE BLOCK ***** */
# $1= cert serial number, $2= file stem
$RPKI_ROOT/testcases/conformance/scripts/gen_child_ca.sh -b crl $2 $1 \
  ../root.cer \
  rsync://rpki.bbn.com/conformance/root.cer ../root.p15 \
  rsync://rpki.bbn.com/conformance/root/root.crl
# 
dump_smart $2.cer >$2.cer.raw
cd $2
dump_smart bad$2.crl >bad$2.raw
# #
cp bad$2.raw bad$2.raw.old
vi bad$2.raw
diff -u bad$2.raw.old bad$2.raw >bad$2.stage0.patch
#
rr <bad$2.raw >bad$2.blb
sign_cert bad$2.blb ../$2.p15
mv bad$2.blb bad$2.crl
dump -a bad$2.crl >bad$2.raw
#
cp bad$2.raw bad$2.raw.old
vi bad$2.raw
diff -u bad$2.raw.old bad$2.raw >bad$2.stage1.patch
rr <bad$2.raw >bad$2.crl
# cp $2.mft $2.old.mft
fix_manifest $2.mft $2.mft.p15 bad$2.crl
