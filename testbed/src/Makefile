#
# Makefile for testbed object creation
#
# $Id: Makefile 535 2008-06-20 18:57:43Z sirois $
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
#  Contributor(s):  Karen Sirois
# 
# ***** END LICENSE BLOCK *****

TARGETS=create_object gen_hash

all:	$(TARGETS)

ifneq ($(CLINCLUDES),)
  CFLAGS += -DDEBUG -I$(CLINCLUDES)
endif

CFLAGS += -g -I../../cg/asn -I../../cg/asn_gen -I../../cg/casn -Wall -DDEBUG
ASN_DIR= ../../cg/asn
CASN_DIR= ../../casn
LIBASN=../../cg/asn/libasn.a
LIBCASN=../../cg/casn/libcasn.a
LIBROA=../../roa-lib/libroa.a
LIBCL=-lcl
LIBCRYPTO=-L/usr/local/ssl/lib -lcrypto
LIBDL=-ldl
LOCAL_LIBS=  $(LIBASN) $(LIBROA) $(LIBCASN)
LIBS=$(LIBCRYPTO) $(LIBCL) $(LIBDL) $(LIBPTHREAD)

create_object: create_object.o create_cert.o create_crl.o create_utils.o create_manifest.o create_roa.o sign_object.o $(LOCAL_LIBS)
	$(CC) $(CFLAGS) -o $@ create_object.o create_cert.o create_crl.o create_utils.o sign_object.o  create_manifest.o create_roa.o $(LOCAL_LIBS) $(LIBS)

gen_hash: gen_hash.o $(LOCAL_LIBS)
	$(CC) $(CFLAGS) -o $@ gen_hash.o $(LOCAL_LIBS) $(LIBS)

clean:
	rm -f $(TARGETS) *.o

