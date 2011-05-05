mv $1.raw $1.raw~
cp badCert.raw $1.raw
diff $1.raw $1.raw~ > tmp
vi tmp
vi $1.raw
rr <$1.raw >$1.blb
sign_cert $1.blb ../root.p15
mv $1.blb $1.cer
dump_smart $1.cer >$1.raw
vi $1.raw
echo finished $1.cer
