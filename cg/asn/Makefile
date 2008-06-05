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

CFLAGS=	-c -I. -I../casn

ASN_GEN=../asn_gen/asn_gen

ASN_SOURCE=\
	Algorithms.asn \
	certificate.asn \
	crlv2.asn \
	extensions.asn \
	keyfile.asn \
	manifest.asn \
	name.asn \
	orname.asn \
	privkey.asn \
	roa.asn \
	serial_number.asn

GENERATED_C_FILES=$(ASN_SOURCE:.asn=.c)
GENERATED_H_FILES=$(ASN_SOURCE:.asn=.h)

OTHER_C_FILES=\
	CertificateToBeSignedConstraint.c \
	CertificateRevocationListToBeSignedConstraint.c

O_FILES=$(GENERATED_C_FILES:.c=.o) $(OTHER_C_FILES:.c=.o)

.SUFFIXES: .asn

.asn.c:
	$(ASN_GEN) -c $<

all:	libasn.a

$(O_FILES): $(GENERATED_C_FILES)

libasn.a: $(O_FILES)
	ar crv libasn.a $(O_FILES)
	ranlib libasn.a

clean:
	rm -f $(GENERATED_C_FILES) $(GENERATED_H_FILES) $(O_FILES) *~

