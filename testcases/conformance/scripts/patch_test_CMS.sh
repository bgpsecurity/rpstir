#!/bin/bash -x

# $1=CMS/ROA/MFT, $2=fault type, $3= roa/roa/mft, $4 =sernum
cp goodEECert.raw bad$1EE$2.raw
rr <bad$1EE$2.raw >bad$1EE$2.cer
put_sernum bad$1EE$2.cer $4
dump -a bad$1EE$2.cer >bad$1EE$2.raw

# Record manual changes to bad$1EE$2.raw
# cp bad$1EE$2.raw bad$1EE$2.raw.old
# vi bad$1EE$2.raw
# diff -u bad$1EE$2.raw.old bad$1EE$2.raw > bad$1$2.stage0.patch
patch  bad$1EE$2.raw  bad$1$2.stage0.patch

rr <bad$1EE$2.raw >bad$1EE$2.cer
# gen_key bad$1EE$2.p15 2048
add_key_info bad$1EE$2.cer bad$1EE$2.p15 ../root.cer
mv bad$1EE$2.cer.raw bad$1EE$2.raw
sign_cert bad$1EE$2.cer ../root.p15
cp good$1.raw bad$1$2.raw

# Record manual changes to bad$1$2.raw
# cp bad$1$2.raw bad$1$2.raw.old
# vi bad$1$2.raw
# diff -u bad$1$2.raw.old bad$1$2.raw > bad$1$2.stage1.patch
patch bad$1$2.raw  bad$1$2.stage1.patch

rr <bad$1$2.raw >bad$1$2.$3
mv bad$1$2.raw bad$1$2.raw.old
add_cms_cert bad$1EE$2.cer bad$1$2.$3 bad$1EE$2.p15 bad$1$2.tmp
mv bad$1$2.tmp bad$1$2.$3
dump_smart bad$1$2.$3 > bad$1$2.$3.raw

# Record manual changes to bad$1$2.$3.raw
# cp bad$1$2.$3.raw bad$1$2.$3.raw.old
# vi bad$1$2.$3.raw
# diff -u bad$1$2.$3.raw.old bad$1$2.$3.raw > bad$1$2.$3.stage2.patch
patch bad$1$2.$3.raw  bad$1$2.$3.stage2.patch

rr <bad$1$2.$3.raw >bad$1$2.$3
