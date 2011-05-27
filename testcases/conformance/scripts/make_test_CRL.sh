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
# $1= file stem, $2= CRL number
cp goodCRL.raw badCRL$1.raw
rr <badCRL$1.raw >badCRL$1.cer
put_sernum badCRL$1.cer $2
dump_smart badCRL$1.cer >badCRL$1.raw
#
cp badCRL$1.raw badCRL$1.raw.old
vi badCRL$1.raw
diff -u badCRL$1.raw.old badCRL$1.raw >badCRL$1.stage0.patch
#
rr <badCRL$1.raw >badCRL$1.blb
sign_cert badCRL$1.blb ../root.p15
mv badCRL$1.blb badCRL$1.cer
dump_smart badCRL$1.cer >badCRL$1.raw
#
cp badCRL$1.raw badCRL$1.raw.old
vi badCRL$1.raw
diff -u badCRL$1.raw.old badCRL$1.raw >badCRL$1.stage1.patch
rr <badCRL$1.raw >badCRL$1.cer
