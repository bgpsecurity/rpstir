#
# Makefile for asn.1 definitions
#
# $Id: Makefile 1135 2010-05-24 13:17:17Z achi $
#
# ***** BEGIN LICENSE BLOCK *****
#  
#  BBN Address and AS Number PKI Database/repository software
#  Version 3.0-bate
#  
#  US government users are permitted unrestricted rights as
#  defined in the FAR.  
# 
#  This software is distributed on an "AS IS" basis, WITHOUT
#  WARRANTY OF ANY KIND, either express or implied.
# 
#  Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.  All Rights Reserved.
# 
#  Contributor(s):  Brenton Kohler
# 
# ***** END LICENSE BLOCK *****

AM_CFLAGS = -g -Wall -I../casn

ASN_GEN=../asn_gen/asn_gen

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
        roa.asn

GENERATED_C_FILES=$(ASN_SOURCE:.asn=.c)
GENERATED_H_FILES=$(ASN_SOURCE:.asn=.h)

OTHER_C_FILES=\
        CertificateToBeSignedConstraint.c \
        CertificateRevocationListToBeSignedConstraint.c


O_FILES=$(GENERATED_C_FILES:.c=.o) $(OTHER_C_FILES:.c=.o)

SUFFIXES: .asn

.asn.c:
	$(ASN_GEN) -c $<

noinst_LIBRARIES = libasn.a

$(O_FILES): $(GENERATED_C_FILES)

libasn_a_SOURCES = $(GENERATED_C_FILES) $(OTHER_C_FILES)

