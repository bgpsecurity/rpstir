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

all:	dump rr bin_to_six six_to_bin loadkey genkey whatsfcs

CFLAGS=	-g -I/usr/local/include -I/usr/local/ssl/include -I../asn -I../asn_gen -I../casn -Wall
ASN_DIR= ../asn
CASN_DIR= ../casn
LOCAL_LIBS= -L$(ASN_DIR) -lasn -L$(CASN_DIR) -lcasn
LIBS= -L/usr/local/lib -L/usr/local/ssl/lib -lcrypto $(LIBCL) $(LIBDL) $(LIBPTHREAD)

dump:	dump.o asn.o asn_dump.o util.o asn.h
	$(CC) $(CFLAGS) -o dump -g dump.o asn.o asn_dump.o util.o

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

genkey:	genkey.o
	$(CC) $(CFLAGS) -o $@ genkey.o $(LOCAL_LIBS) $(LIBS)

clean:
	rm -f dump rr bin_to_six six_to_bin whatsfcs loadkey genkey *.o

