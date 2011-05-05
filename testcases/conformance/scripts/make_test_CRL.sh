# $1 file stem, $2 cert sernum 
# make CA cert
# cd badCRL$1
cp ../goodCRL.raw badCRL$1.raw
echo vi badCRL$1.raw
vi badCRL$1.raw
rr <badCRL$1.raw >badCRL$1.blb
echo sign_cert
sign_cert badCRL$1.blb ../testCRL$1.p15
echo move badCRL$1.blb to badCRL$1.crl
mv badCRL$1.blb badCRL$1.crl
echo dump_smart badCRL$1.crl
dump_smart badCRL$1.crl >badCRL$1.raw
echo check
vi badCRL$1.raw
echo done
