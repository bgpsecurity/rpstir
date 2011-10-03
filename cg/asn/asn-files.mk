ASN_SOURCE= \
	Algorithms.asn \
	name.asn \
	serial_number.asn \
        orname.asn \
	extensions.asn \
	crlv2.asn \
	keyfile.asn \
	certificate.asn \
        manifest.asn \
	privkey.asn \
        roa.asn \
        blob.asn

GENERATED_C_FILES=$(ASN_SOURCE:.asn=.c)
GENERATED_H_FILES=$(ASN_SOURCE:.asn=.h)
GENERATED_O_FILES=$(ASN_SOURCE:.asn=.$(OBJEXT))
