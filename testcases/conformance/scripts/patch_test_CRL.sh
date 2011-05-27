#!/bin/bash -x
# $1= file stem, $2= CRL number
cp goodCRL.raw badCRL$1.raw
rr <badCRL$1.raw >badCRL$1.cer
put_sernum badCRL$1.cer $2
dump_smart badCRL$1.cer >badCRL$1.raw
#
# cp badCRL$1.raw badCRL$1.raw.old
# vi badCRL$1.raw
# diff -u badCRL$1.raw.old badCRL$1.raw >badCRL$1.stage0.patch
patch badCRL$1.raw >badCRL$1.stage0.patch
#
rr <badCRL$1.raw >badCRL$1.blb
sign_cert badCRL$1.blb ../root.p15
mv badCRL$1.blb badCRL$1.cer
dump_smart badCRL$1.cer >badCRL$1.raw
#
# cp badCRL$1.raw badCRL$1.raw.old
# vi badCRL$1.raw
# diff -u badCRL$1.raw.old badCRL$1.raw >badCRL$1.stage1.patch
patch badCRL$1.raw >badCRL$1.stage1.patch
#
rr <badCRL$1.raw >badCRL$1.cer
