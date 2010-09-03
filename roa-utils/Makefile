#
# Makefile for roa libs and test code
#
# $Id$
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
#  Contributor(s):  Joshua Gruenspecht, Mark Reynolds
# 
# ***** END LICENSE BLOCK *****


# Rearrangement for building of .h files in FreeBSD
CFLAGS += -I../proto

ifneq ($(MYSQLINCLUDES),)
  CFLAGS += -I$(MYSQLINCLUDES)
endif

ifneq ($(SSLINCLUDES),)
  CFLAGS += -I$(SSLINCLUDES)
endif

CFLAGS += -I$(CLINCLUDES) -I../cg/asn -I../cg/asn_gen -I../cg/casn -I../roa-lib\
	-g -Wall -Wshadow -Wmissing-prototypes -Wmissing-declarations

TEST_OBJECTS= roa_test.o
LIBASN= ../cg/asn/libasn.a
LIBCASN=../cg/casn/libcasn.a
LIBRPKI=../proto/librpki.a
PROTO_DIR= ../proto
ROA_LIB_DIR=../roa-lib
LIBROA=$(ROA_LIB_DIR)/libroa.a

LOCAL_LIBS=$(LIBRPKI) $(LIBROA)	$(LIBASN) $(LIBCASN) 
OTHER_LIBS=$(LIBCL) $(LIBSSL) $(LIBCRYPTO) $(LIBODBC) $(LIBXTRA) $(LIBDL) $(LIBPTHREAD)

# --- targets
TARGETS=roa_test test_val2 test_check_sig sign_roa test_hash make_manifest make_roa 
all:    $(TARGETS)

roa_test: $(TEST_OBJECTS) 
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJECTS) $(LOCAL_LIBS) $(OTHER_LIBS)

roa_test.o: roa_test.c

test_check_sig: test_check_sig.o
	$(CC) $(CFLAGS) -o $@ test_check_sig.o $(LOCAL_LIBS) $(OTHER_LIBS)

test_val2: test_val2.o $(LIBCASN)
	$(CC) $(CFLAGS) -o $@ test_val2.o $(LOCAL_LIBS) $(OTHER_LIBS)

test_hash: test_hash.o ../cg/casn/libcasn.a
	$(CC) $(CFLAGS) -o $@ test_hash.o $(LOCAL_LIBS) $(OTHER_LIBS)

make_manifest: make_manifest.o $(LIBCASN)
	$(CC) $(CFLAGS) -o $@ make_manifest.o $(LOCAL_LIBS) $(OTHER_LIBS)

make_roa: make_roa.o $(LIBCASN)
	$(CC) $(CFLAGS) -o $@ make_roa.o $(LOCAL_LIBS) $(OTHER_LIBS)

sign_roa: sign_roa.o $(LIBCASN)
	$(CC) $(CFLAGS) -o $@ sign_roa.o $(LOCAL_LIBS) $(OTHER_LIBS)

make_manifest.o: make_manifest.c $(ROA_LIB_DIR)/roa_utils.h 

make_roa.o:	make_roa.c $(ROA_LIB_DIR)/roa_utils.h

read_roa.o:	read_roa.c $(ROA_LIB_DIR)/roa_utils.h


clean:
	rm -f $(TARGETS) *.o

clean2:
	rm -f *.pem *.der *.txt
