all:	Algorithms.h extensions.h name.h orname.h roa.h serial_number.h certificate.h crlv2.h

Algorithms.h:	Algorithms.asn
	../asn_gen/asn_gen -c Algorithms.asn

extensions.h:	extensions.asn
	../asn_gen/asn_gen -c extensions.asn

name.h:	name.asn
	../asn_gen/asn_gen -c name.asn

orname.h:	orname.asn
	../asn_gen/asn_gen -c orname.asn

roa.h:	roa.asn
	../asn_gen/asn_gen -c roa.asn

serial_number.h:	serial_number.asn
	../asn_gen/asn_gen -c serial_number.asn

certificate.h:	certificate.asn
	../asn_gen/asn_gen -c certificate.asn

crlv2.h:	crlv2.asn
	../asn_gen/asn_gen -c crlv2.asn

clean:
	rm -f *.h *.o
