# $1=CMS/ROA/MFT, $2=fault type, $3= roa/roa/mft, $4 =sernum
echo bad$1EE$2.raw
cp goodEECert.raw bad$1EE$2.raw
rr <bad$1EE$2.raw >bad$1EE$2.cer
put_sernum bad$1EE$2.cer $4
dump_smart bad$1EE$2.cer >bad$1EE$2.raw
vi bad$1EE$2.raw
rr <bad$1EE$2.raw >bad$1EE$2.cer
gen_key bad$1EE$2.p15 2048
add_key_info bad$1EE$2.cer bad$1EE$2.p15 ../root.cer
cp bad$1EE$2.cer.raw bad$1EE$2.raw
echo added key info
sign_cert bad$1EE$2.cer ../root.p15
cp good$1.raw bad$1$2.raw
vi bad$1$2.raw
rr <bad$1$2.raw >bad$1$2.$3
echo did rr for bad$1$2.$3
add_cms_cert bad$1EE$2.cer bad$1$2.$3 bad$1EE$2.p15 bad$1$2.tmp
cp bad$1$2.tmp bad$1$2.$3
echo added cms cert
dump_smart bad$1$2.$3 > bad$1$2.$3.raw
vi bad$1$2.$3.raw
rr <bad$1$2.$3.raw >bad$1$2.$3
echo Made bad$1$2.$3
