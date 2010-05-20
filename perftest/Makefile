#
# Makefile for performance test cases
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
#  Copyright (C) BBN Technologies 2007-2010.  All Rights Reserved.
# 
#  Contributor(s):  Mark Reynolds
# 
# ***** END LICENSE BLOCK *****

# cryptlib
LIBCL=-lcl

# where to find the OpenSSL crypto lib
LIBCRYPTO=-L/usr/local/ssl/lib -lcrypto

# dlopen
LIBDL=-ldl 

# where to find the odbc library
LIBODBC=-L/usr/local/lib -lmyodbc3

# in libc on newer Linux distros
LIBPTHREAD= 

# nothing extra
LIBXTRA=

# where to find OpenSSL include files
SSLINCLUDES=/usr/local/ssl/include

# where to find ODBC include files
ODBCINCLUDES=/usr/local/include

# where to find MySQL include files
MYSQLINCLUDES=/usr/local/include

# where to find cryptlib includes
CLINCLUDES=/usr/local/include

TARGETS=make_perf_cert 

all:	$(TARGETS)

CFLAGS=	-g -I$(SSLINCLUDES) -I../cg/asn -I../cg/asn_gen -I../cg/casn -Wall -I../roa-lib -I$(CLINCLUDES)
ASN_DIR= ../cg/asn
CASN_DIR= ../casn
LIBASN=../cg/asn/libasn.a
LIBCASN=../cg/casn/libcasn.a
LIBROA=../roa-lib/libroa.a
LOCAL_LIBS=  $(LIBASN) $(LIBROA) $(LIBCASN)
LIBS=$(LIBCRYPTO) $(LIBCL) $(LIBDL) $(LIBPTHREAD)

make_perf_cert:	make_perf_cert.o Makefile $(LOCAL_LIBS)
	$(CC) $(CFLAGS) -o $@ make_perf_cert.o $(LOCAL_LIBS) $(LIBS)


clean:
	rm -f $(TARGETS) *.o

