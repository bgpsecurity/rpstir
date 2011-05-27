#!/bin/bash -x
# $1= file stem, $2= serial number
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
dump -a badCert$1.cer >badCert$1.raw
#
cp badCert$1.raw badCert$1.raw.old
vi badCert$1.raw
diff -u badCert$1.raw.old badCert$1.raw >badCert$1.stage1.patch
