# $1= file stem, $2= serial number
echo cp goodCert
cp goodCert.raw badCert$1.raw
rr <badCert$1.raw >badCert$1.cer
put_sernum badCert$1.cer $2
echo did sernum
dump_smart badCert$1.cer >badCert$1.raw
echo vi badCert$1.raw
vi badCert$1.raw
echo rr
rr <badCert$1.raw >badCert$1.blb
echo sign_cert
sign_cert badCert$1.blb ../root.p15
echo move badCert$1.blb to badCert$1.cer
mv badCert$1.blb badCert$1.cer
echo dump_smart badCert$1.cer
dump_smart badCert$1.cer >badCert$1.raw
echo check
vi badCert$1.raw
echo done
