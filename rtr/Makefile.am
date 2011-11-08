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

AM_CFLAGS = -g -Wall -Wextra

AM_CPPFLAGS = $(DEPS_CFLAGS) -I../cg/asn -I../proto -I../cg/asn_gen \
	-I../cg/casn -I../roa-lib -I../utils


bin_PROGRAMS = doUpdate rtrd

EXTRA_DIST = \
	cleanServerData

doUpdate_SOURCES = doUpdate.c
doUpdate_LDFLAGS = $(LIBS)
doUpdate_LDADD = ../proto/librpki.a ../utils/libutils.a
doUpdate_CFLAGS = $(AM_CFLAGS) -DHAVE_LONG_LONG

rtrd_SOURCES = \
	cache_state.h \
	connection.c connection.h \
	connection_control.c connection_control.h \
	db.c db.h \
	pdu.h
rtrd_LDADD = ../utils/libutilsdebug.a # TODO: switch to libutils.a before merging into master
rtrd_CFLAGS = $(AM_CFLAGS) -Werror
