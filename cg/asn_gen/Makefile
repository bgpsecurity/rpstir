#
# Makefile for asn.1 compiler
#
# $Id$
#

all:	asn_gen

#CC=	gcc
CFLAGS=	-DINTEL -Dconstruct=cconstruct -Ddo_hdr=cdo_hdr -Dasn_constr_id=casn_constr_id -Dasn_hdr_id=casn_hdr_id -I. -I../casn

asn_gen:	asn_gen.o asn_java.o asn_pproc.o asn_pprocx.o asn_read.o asn_tabulate.o casn_constr.o casn_hdr.o
	$(CC) -o asn_gen $(CFLAGS) -L../casn asn_gen.o asn_java.o asn_pproc.o asn_pprocx.o asn_read.o asn_tabulate.o casn_constr.o casn_hdr.o -lcasn

clean:
	rm -f *.o asn_gen
