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

TARGET=libasn.a
ASNFILES=Algorithms.asn extensions.asn name.asn orname.asn privkey.asn roa.asn manifest.asn serial_number.asn certificate.asn crlv2.asn keyfile.asn 
HFILES=$(ASNFILES:.asn=.h)
CFILES=$(ASNFILES:.asn=.c) CertificateToBeSignedConstraint.c CertificateRevocationListToBeSignedConstraint.c
OFILES=$(CFILES:.c=.o)

all: $(HFILES) $(TARGET)

CFLAGS=	-c -g -I. -I../casn

$(TARGET): $(OFILES)
	ar crv $(TARGET) $(CFILES:.c=.o)
	ranlib $(TARGET)

%.h %.c: %.asn
	../asn_gen/asn_gen -c $<

clean:
	rm -f $(ASNFILES:.asn=.c) $(ASNFILES:.asn=.h) $(TARGET) *.o
