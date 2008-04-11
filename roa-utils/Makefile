#
# Makefile for roa libs and test code
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
#  Contributor(s):  Joshua Gruenspecht, Mark Reynolds
# 
# ***** END LICENSE BLOCK *****

# --- macros
#CC=gcc
CFLAGS=	-g -I/usr/local/include -I/usr/local/ssl/include -I../cg/asn -I../cg/asn_gen -I../cg/casn -I../proto -Wall -Wshadow -Wmissing-prototypes -Wmissing-declarations
TEST_OBJECTS= roa_test.o
ASN_DIR= ../cg/asn
CASN_DIR= ../cg/casn
PROTO_DIR= ../proto
LOCAL_LIBS= -L. -L$(PROTO_DIR) -L$(ASN_DIR) -L$(CASN_DIR) -lapki -lroa -lasn -lcasn $(LIBCL)
SSL_LIBS= -L/usr/local/ssl/lib -lssl -lcrypto -L/usr/local/lib -lmyodbc3 $(LIBXTRA)  $(LIBDL) $(LIBPTHREAD)
#-lrt
AR= ar
RANLIB= ranlib

# --- targets
all:    libroa.a roa_test test_val2 test_check_sig sign_roa test_manifest test_hash make_manifest

b64:	b64.o
	$(CC) $(CFLAGS) $(CFLAGS) -c b64.c
	$(CC) $(CFLAGS) -o $@ b64.o

#roa_test: roa_test.o roa_serialize.o Makefile
#	$(CC) $(CFLAGS) -o roa_test -g -L/usr/local/ssl/lib roa_test.o roa_validate.o roa.o

roa_test:   libroa.a $(TEST_OBJECTS) 
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJECTS) $(LOCAL_LIBS) $(SSL_LIBS)

roa_test.o: roa_test.c libroa.a Makefile

test_check_sig: test_check_sig.o
	$(CC) $(CFLAGS) -o $@ test_check_sig.o $(LOCAL_LIBS) $(SSL_LIBS)

test_manifest: test_manifest.o manifest_validate.o ../cg/casn/libcasn.a
	$(CC) $(CFLAGS) -o $@ test_manifest.o $(LOCAL_LIBS) $(SSL_LIBS)

test_val2: test_val2.o roa_validate.o ../cg/casn/libcasn.a
	$(CC) $(CFLAGS) -o $@ test_val2.o $(LOCAL_LIBS) $(SSL_LIBS)

test_hash: test_hash.o roa_validate.o ../cg/casn/libcasn.a
	$(CC) $(CFLAGS) -o $@ test_hash.o $(LOCAL_LIBS) $(SSL_LIBS)

make_manifest: make_manifest.o ../cg/casn/libcasn.a
	$(CC) $(CFLAGS) -o $@ make_manifest.o $(LOCAL_LIBS) $(SSL_LIBS)

sign_roa: sign_roa.o ../cg/casn/libcasn.a
	$(CC) $(CFLAGS) -o $@ sign_roa.o $(LOCAL_LIBS) $(SSL_LIBS)

roa_validate.o: roa_validate.c roa_utils.h Makefile
roa_create.o: roa_create.c roa_utils.h Makefile
roa_general.o: roa_general.c roa_utils.h Makefile
roa_serialize.o: roa_serialize.c roa_utils.h Makefile
manifest_validate.o: manifest_validate.c roa_utils.h Makefile
make_manifest.o: make_manifest.c roa_utils.h Makefile

libroa.a:	roa_validate.o roa_create.o roa_general.o roa_serialize.o roa_utils.h manifest_validate.o
	ar crv libroa.a roa_validate.o roa_create.o roa_general.o roa_serialize.o manifest_validate.o
	ranlib libroa.a

clean:
	rm -f roa_test test_val2 test_check_sig test_hash *.a *.o

clean2:
	rm -f *.pem *.der *.txt
