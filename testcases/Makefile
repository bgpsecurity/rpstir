#
# Makefile for test cases
#
# $Id: Makefile 535 2008-06-20 18:57:43Z gardiner $
#
# ***** BEGIN LICENSE BLOCK *****
#  
#  BBN Address and AS Number PKI Database/repository software
#  Version 3.0-beta
#  
#  US government users are permitted unrestricted rights as
#  defined in the FAR.  
# 
#  This software is distributed on an "AS IS" basis, WITHOUT
#  WARRANTY OF ANY KIND, either express or implied.
# 
#  Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.  All Rights Reserved.
# 
#  Contributor(s):  Mark Reynolds
# 
# ***** END LICENSE BLOCK *****

TARGETS=make_test_cert make_test_crl make_test_roa make_test_manifest  gen_test_key cert_validate

all:	$(TARGETS)

ifneq ($(MYSQLINCLUDES),)
  CFLAGS += -I$(MYSQLINCLUDES)
endif

ifneq ($(SSLINCLUDES),)
  CFLAGS += -I$(SSLINCLUDES)
endif

ifneq ($(CLINCLUDES),)
  CFLAGS += -I$(CLINCLUDES)
endif

CFLAGS += -g -I../cg/asn -I../cg/asn_gen -I../cg/casn -Wall -I../roa-lib
ASN_DIR= ../cg/asn
CASN_DIR= ../casn
LIBASN=../cg/asn/libasn.a
LIBCASN=../cg/casn/libcasn.a
LIBROA=../roa-lib/libroa.a
LOCAL_LIBS=  $(LIBASN) $(LIBROA) $(LIBCASN)
LIBS=$(LIBCRYPTO) $(LIBCL) $(LIBDL) $(LIBPTHREAD)

gen_test_key:	gen_test_key.o Makefile $(LOCAL_LIBS)
	$(CC) $(CFLAGS) -o $@ gen_test_key.o $(LOCAL_LIBS) $(LIBS)

make_test_cert:	make_test_cert.o Makefile adjustTime.o $(LOCAL_LIBS)
	$(CC) $(CFLAGS) -o $@ adjustTime.o make_test_cert.o $(LOCAL_LIBS) $(LIBS)

make_test_crl:	make_test_crl.o Makefile adjustTime.o $(LOCAL_LIBS)
	$(CC) $(CFLAGS) -o $@ make_test_crl.o adjustTime.o $(LOCAL_LIBS) $(LIBS)

make_test_roa:	make_test_roa.o Makefile $(LOCAL_LIBS)
	$(CC) $(CFLAGS) -o $@ make_test_roa.o $(LOCAL_LIBS) $(LIBS)

make_test_manifest:	make_test_manifest.o Makefile adjustTime.o $(LOCAL_LIBS)
	$(CC) $(CFLAGS) -o $@ make_test_manifest.o adjustTime.o $(LOCAL_LIBS) $(LIBS)

cert_validate:	cert_validate.o Makefile $(LOCAL_LIBS)
	$(CC) $(CFLAGS) -o $@ cert_validate.o  $(LOCAL_LIBS) $(LIBS)

cert_validate.o:	cert_validate.c

adjustTime.o:	adjustTime.c 


signCMS.o:	signCMS.c
clean:
	rm -f $(TARGETS) *.o

