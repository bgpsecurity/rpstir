
JFLAGS = -g
OUTDIR = "../lib"

default: ruleEditor_app

all:  cert orname_dir pkcs10_dir rules_dir skaction_dir asn_dir name_dir \
	extensions_dir crlv2_dir algorithms_dir ruleEditor_app

orname_dir:	
	(cd orname && make)

name_dir:   
	(cd name && make)

algorithms_dir:	
	(cd algorithms && make)

ruleEditor_app:  
	(cd ruleEditor && make)

cert:
	(cd certificate && make)

pkcs10_dir: 
	(cd pkcs10 && make)

rules_dir:  
	(cd rules && make)	

skaction_dir: 
	(cd skaction && make)

asn_dir:	
	(cd asn && make)

extensions_dir:	
	(cd extensions && make)

crlv2_dir:	
	(cd crlv2 && make)

clean:
	-rm ${OUTDIR}/ruleEditor/*.class
	-rm ${OUTDIR}/certificate/*.class
	-rm ${OUTDIR}/orname/*.class
	-rm ${OUTDIR}/pkcs10/*.class
	-rm ${OUTDIR}/rules/*.class
	-rm ${OUTDIR}/skaction/*.class
	-rm ${OUTDIR}/asn/*.class
	-rm ${OUTDIR}/name/*.class
	-rm ${OUTDIR}/extensions/*.class
	-rm ${OUTDIR}/crlv2/*.class
	-rm ${OUTDIR}/Algorithms/*.class
