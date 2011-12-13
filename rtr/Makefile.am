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

AM_CFLAGS = -g -Wall -Wextra -Werror

AM_CPPFLAGS = $(DEPS_CFLAGS) -I../cg/asn -I../proto -I../cg/asn_gen \
	-I../cg/casn -I../roa-lib -I../utils

noinst_LIBRARIES = libpdu.a

bin_PROGRAMS = @PACKAGE_NAME@-rtr-update @PACKAGE_NAME@-rtrd
noinst_PROGRAMS = rtr-test-client

EXTRA_DIST = \
	cleanServerData

libpdu_a_SOURCES = pdu.c pdu.h

@PACKAGE_NAME@_rtr_update_SOURCES = rtr-update.c
@PACKAGE_NAME@_rtr_update_LDFLAGS = $(LIBS)
@PACKAGE_NAME@_rtr_update_LDADD = ../proto/librpki.a ../utils/libutils.a
@PACKAGE_NAME@_rtr_update_CFLAGS = $(AM_CFLAGS) -DHAVE_LONG_LONG

@PACKAGE_NAME@_rtrd_SOURCES = \
	cache_state.c cache_state.h \
	config.h \
	connection.c connection.h \
	connection_control.c connection_control.h \
	db.c db.h \
	main.c \
	semaphores.h \
	signals.c signals.h
@PACKAGE_NAME@_rtrd_LDADD = libpdu.a ../utils/libutils.a ../utils/mysql-c-api/libmysqlcapi.a

rtr_test_client_SOURCES = test-client.c
rtr_test_client_LDADD = libpdu.a ../utils/libutils.a
