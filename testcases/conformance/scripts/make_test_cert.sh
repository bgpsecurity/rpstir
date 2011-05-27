#!/bin/bash -x
# $1= file stem, $2= serial number
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
