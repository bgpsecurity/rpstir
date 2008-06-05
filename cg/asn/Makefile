#
# Makefile for asn.1 definitions
#
# $Id$
#
# ***** BEGIN LICENSE BLOCK *****
#  
#  BBN Address and AS Number PKI Database/repository software
#  Version 1.0
#  
#  US government users are permitted unrestricted rights as
#  defined in the FAR.  
# 
#  This software is distributed on an "AS IS" basis, WITHOUT
#  WARRANTY OF ANY KIND, either express or implied.
# 
#  Copyright (C) BBN Technologies 2007.  All Rights Reserved.
# 
#  Contributor(s):  Mark Reynolds
# 
# ***** END LICENSE BLOCK *****

GENERATED_C_FILES=Algorithms.c extensions.c name.c orname.c privkey.c roa.c manifest.c serial_number.c certificate.c crlv2.c 

all:	$(GENERATED_C_FILES) libasn.a

Algorithms.c Algorithms.h:	Algorithms.asn
	../asn_gen/asn_gen -c Algorithms.asn

extensions.c extensions.h:	extensions.asn
	../asn_gen/asn_gen -c extensions.asn

name.c name.h:	name.asn
	../asn_gen/asn_gen -c name.asn

orname.c orname.h:	orname.asn
	../asn_gen/asn_gen -c orname.asn

privkey.c privkey.h:	privkey.asn
	../asn_gen/asn_gen -c privkey.asn

roa.c roa.h:	roa.asn
	../asn_gen/asn_gen -c roa.asn

manifest.c manifest.h:	manifest.asn
	../asn_gen/asn_gen -c manifest.asn

serial_number.c serial_number.h:	serial_number.asn
	../asn_gen/asn_gen -c serial_number.asn

certificate.c certificate.h:	certificate.asn
	../asn_gen/asn_gen -c certificate.asn

crlv2.c crlv2.h:	crlv2.asn
	../asn_gen/asn_gen -c crlv2.asn

CFLAGS=	-c -I. -I../casn

libasn.a:	Algorithms.o extensions.o name.o orname.o privkey.o roa.o serial_number.o certificate.o crlv2.o manifest.o CertificateToBeSignedConstraint.o CertificateRevocationToBeSignedConstraint.o
	ar crv libasn.a *.o
	ranlib libasn.a

clean:
	rm -f $(GENERATED_C_FILES) *.h *.o *.a
