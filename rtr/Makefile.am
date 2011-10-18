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
#  Copyright (C) Raytheon BBN Technologies Corp. 2007.  All Rights Reserved.
# 
#  Contributor(s):  Brenton Kohler
# 
# ***** END LICENSE BLOCK *****

AM_CFLAGS = -g -I../cg/asn -I../proto -I../cg/asn_gen -I../cg/casn -Wall -I../roa-lib \
	-Wshadow -Wmissing-prototypes -Wmissing-declarations -DHAVE_LONG_LONG

LDADD = libpdu.a ../proto/librpki.a ../utils/libutils.a

bin_PROGRAMS = testClient server doUpdate sampleClient
noinst_LIBRARIES = libpdu.a

EXTRA_DIST = \
	cleanServerData \
	doServer \
	INSTRUCTIONS \
	runTestServer \
	sampleHostsFile \
	startAgent.sh \
	testlog.1 \
	testlog.2 \
	testlog.3 \
	testSpecs

testClient_SOURCES = testClient.c
testClient_LDFLAGS = $(LIBS)
server_SOURCES = server.c
server_LDFLAGS = $(LIBS)
doUpdate_SOURCES = doUpdate.c
doUpdate_LDFLAGS = $(LIBS)
sampleClient_SOURCES = sampleClient.c
sampleClient_LDFLAGS = $(LIBS)

libpdu_a_SOURCES = pdu.h pdu.c sshComms.h sshComms.c socket.h socket.c \
	rtrUtils.h rtrUtils.c coreClient.h coreClient.c
