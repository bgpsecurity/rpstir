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

TARGETS=test_casn_random dump rr bin_to_six six_to_bin six2hex \
	loadkey gen_key whatsfcs make_oidtable make_TA set_cert_ski  \
	sign_cert add_key_info read_roa encode-oid dumpasn1 dump_smart

all:	$(TARGETS)

CFLAGS=	-g -I$(SSLINCLUDES) -I../asn -I../asn_gen -I../casn -Wall -I../../roa-lib -I$(CLINCLUDES)
ASN_DIR= ../asn
CASN_DIR= ../casn
LOCAL_LIBS= -L$(ASN_DIR) -lasn -L$(CASN_DIR) -lcasn
LIBS=$(LIBCRYPTO) $(LIBCL) $(LIBDL) $(LIBPTHREAD)

dumpasn1: dumpasn1.c
	$(CC) -g -o dumpasn1 dumpasn1.c

encode-oid: encode-oid.c
	$(CC) -g -o encode-oid encode-oid.c

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

six2hex:	six2hex.o prencode.o 
	$(CC) $(CFLAGS) -o six2hex six2hex.o prencode.o 

whatsfcs:	whatsfcs.o prencode.o 
	$(CC) $(CFLAGS) -o whatsfcs whatsfcs.o

make_oidtable:	make_oidtable.o Makefile ../casn/libcasn.a ../asn/libasn.a
	$(CC) $(CFLAGS) -o $@ make_oidtable.o 

gen_key: gen_key.o Makefile ../casn/libcasn.a ../asn/libasn.a
	$(CC) $(CFLAGS) -o $@ $< $(LOCAL_LIBS) $(LIBS)

make_TA: make_TA.o Makefile ../casn/libcasn.a ../asn/libasn.a
	$(CC) $(CFLAGS) -o $@ $< $(LOCAL_LIBS) $(LIBS)

sign_cert: sign_cert.o Makefile ../casn/libcasn.a ../asn/libasn.a
	$(CC) $(CFLAGS) -o $@ $< $(LOCAL_LIBS) $(LIBS)

add_key_info: add_key_info.o Makefile ../casn/libcasn.a ../asn/libasn.a
	$(CC) $(CFLAGS) -o $@ $< $(LOCAL_LIBS) $(LIBS)

loadkey:	loadkey.o 
	$(CC) $(CFLAGS) -o $@ loadkey.o $(LOCAL_LIBS) $(LIBS)

set_cert_ski:	set_cert_ski.o Makefile ../casn/libcasn.a ../asn/libasn.a
	$(CC) $(CFLAGS) -o $@ set_cert_ski.o $(LOCAL_LIBS) $(LIBS)

dump_smart:	dump_smart.o Makefile ../casn/libcasn.a ../asn/libasn.a
	$(CC) $(CFLAGS) -o $@ dump_smart.o $(LOCAL_LIBS) $(LIBS)

test_casn_random: test_casn_random.o
	$(CC) $(CFLAGS) -o $@ test_casn_random.o $(LOCAL_LIBS)

clean:
	rm -f $(TARGETS) *.o

