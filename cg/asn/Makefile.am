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

SUFFIXES: .asn

AM_CFLAGS = -g -Wall -I../casn

ASN_GEN=../asn_gen/asn_gen

include asn-files.mk

OTHER_C_FILES=\
        CertificateToBeSignedConstraint.c \
        CertificateRevocationListToBeSignedConstraint.c
OTHER_O_FILES=$(OTHER_C_FILES:.c=.$(OBJEXT))

$(OTHER_O_FILES): $(GENERATED_H_FILES)

%.c %.h: %.asn
	$(ASN_GEN) -c $<

noinst_LIBRARIES = libasn.a

libasn_a_SOURCES = $(ASN_SOURCE) $(OTHER_C_FILES)
libasn_a_LIBADD = $(GENERATED_O_FILES)

CLEANFILES = $(GENERATED_C_FILES) $(GENERATED_H_FILES)
EXTRA_DIST = oidtable
