#
# $Id: Makefile 735 2008-10-09 22:51:55Z fbronzo $
#
# Makefile for local cache as server program and test programs
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
#  Contributor(s):  David Montana
# 
# ***** END LICENSE BLOCK *****

all:	libpdu.a # server testClient

ifneq ($(MYSQLINCLUDES),)
  CFLAGS += -I$(MYSQLINCLUDES)
endif

ifneq ($(SSLINCLUDES),)
  CFLAGS += -I$(SSLINCLUDES)
endif

CFLAGS += -I../proto \
	-g -Wall -Wshadow -Wmissing-prototypes -Wmissing-declarations \
	-DHAVE_LONG_LONG

LOCAL_LIBS=./libpdu ../proto/libapki.a

LIBS=$(LIBSSL) $(LIBCL) $(LIBCRYPTO) \
     $(LIBODBC) $(LIBXTRA) $(LIBDL) $(LIBPTHREAD)


pdu.o: pdu.h
server.o: pdu.h
testClient.o: pdu.h

libpdu.a:	pdu.o
	ar crv libapki.a pdu.o
	ranlib libapki.a

server:	server.o libpdu.a $(LOCAL_LIBS) Makefile
	$(CC) -o server -g server.o $(LOCAL_LIBS) $(LIBS)

clean:
	rm -f server *.o *.a
