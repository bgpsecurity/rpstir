#
# Makefile for asn.1 definitions
#
# $Id$
#

all:	Algorithms.h extensions.h name.h orname.h roa.h serial_number.h certificate.h crlv2.h libasn.a

Algorithms.c Algorithms.h:	Algorithms.asn
	../asn_gen/asn_gen -c Algorithms.asn

extensions.c extensions.h:	extensions.asn
	../asn_gen/asn_gen -c extensions.asn

name.c name.h:	name.asn
	../asn_gen/asn_gen -c name.asn

orname.c orname.h:	orname.asn
	../asn_gen/asn_gen -c orname.asn

roa.c roa.h:	roa.asn
	../asn_gen/asn_gen -c roa.asn

serial_number.c serial_number.h:	serial_number.asn
	../asn_gen/asn_gen -c serial_number.asn

certificate.c certificate.h:	certificate.asn
	../asn_gen/asn_gen -c certificate.asn

crlv2.c crlv2.h:	crlv2.asn
	../asn_gen/asn_gen -c crlv2.asn

CFLAGS=	-c -I. -I../casn

Algorithms.o:	Algorithms.c
extensions.o:	extensions.c
name.o:	name.c
orname.o:	orname.c
roa.o:	roa.c
serial_number.o:	serial_number.c
certificate.o:	certificate.c
crlv2.o:	crlv2.c

libasn.a:	Algorithms.o extensions.o name.o orname.o roa.o serial_number.o certificate.o crlv2.o
	ar crv libasn.a *.o
	ranlib libasn.a

clean:
	rm -f *.c *.h *.o *.a
