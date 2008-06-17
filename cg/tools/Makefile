#
# Makefile for asn.1 tools
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

TARGETS=dump rr bin_to_six six_to_bin loadkey genkey whatsfcs set_cert_ski  make_cert make_crl make_roa make_manifest read_roa

all:	$(TARGETS)

CFLAGS=	-g -I$(SSLINCLUDES) -I../asn -I../asn_gen -I../casn -Wall -I../../roa-lib -I$(CLINCLUDES)
ASN_DIR= ../asn
CASN_DIR= ../casn
LOCAL_LIBS= -L$(ASN_DIR) -lasn -L$(CASN_DIR) -lcasn
LIBS=$(LIBCRYPTO) $(LIBCL) $(LIBDL) $(LIBPTHREAD)

dump:	dump.o asn.o asn_dump.o util.o asn.h
	$(CC) $(CFLAGS) -o dump -g dump.o asn.o asn_dump.o util.o

read_roa:	read_roa.o 
	$(CC) $(CFLAGS) -o $@ read_roa.o $(LOCAL_LIBS) $(LIBS)

rr:	rr.o md2.o asn.o asn.h
	$(CC) $(CFLAGS) -o rr -g rr.o md2.o asn.o

bin_to_six:	bin_to_six.o prencode.o 
	$(CC) $(CFLAGS) -o bin_to_six bin_to_six.o prencode.o 

six_to_bin:	six_to_bin.o prencode.o 
	$(CC) $(CFLAGS) -o six_to_bin six_to_bin.o prencode.o 

whatsfcs:	whatsfcs.o prencode.o 
	$(CC) $(CFLAGS) -o whatsfcs whatsfcs.o

loadkey:	loadkey.o
	$(CC) $(CFLAGS) -o $@ loadkey.o $(LOCAL_LIBS) $(LIBS)

genkey:	genkey.o Makefile
	$(CC) $(CFLAGS) -o $@ genkey.o $(LOCAL_LIBS) $(LIBS)

make_cert:	make_cert.o Makefile ../casn/libcasn.a ../asn/libasn.a
	$(CC) $(CFLAGS) -o $@ make_cert.o $(LOCAL_LIBS) $(LIBS)

make_crl:	make_crl.o Makefile ../casn/libcasn.a ../asn/libasn.a
	$(CC) $(CFLAGS) -o $@ make_crl.o $(LOCAL_LIBS) $(LIBS)

make_roa:	make_roa.o Makefile ../casn/libcasn.a ../asn/libasn.a
	$(CC) $(CFLAGS) -o $@ make_roa.o $(LOCAL_LIBS) $(LIBS)

make_manifest:	make_manifest.o Makefile ../casn/libcasn.a ../asn/libasn.a
	$(CC) $(CFLAGS) -o $@ make_manifest.o $(LOCAL_LIBS) $(LIBS)

set_cert_ski:	set_cert_ski.o Makefile ../casn/libcasn.a ../asn/libasn.a
	$(CC) $(CFLAGS) -o $@ set_cert_ski.o $(LOCAL_LIBS) $(LIBS)

clean:
	rm -f $(TARGETS) *.o

