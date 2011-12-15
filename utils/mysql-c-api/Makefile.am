#
# Makefile for a MySQL utility using the C API
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
#  Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.
#  All Rights Reserved.
# 
#  Contributor(s):  Tony Weber
# 
# ***** END LICENSE BLOCK *****

#SUBDIRS = .

AM_CFLAGS = -g -Wall -Wextra -Werror
AM_CPPFLAGS = $(DEPS_CFLAGS) -I.. -I../../rtr

noinst_LIBRARIES = libmysqlcapi.a
check_PROGRAMS = test-driver

libmysqlcapi_a_SOURCES = \
	connect.c connect.h \
	db-internal.h \
	prep-stmt.c prep-stmt.h \
	rtr.c rtr.h \
	util.c util.h

test_driver_SOURCES = test-driver.c test-driver.h 
test_driver_LDADD = ../libutils.a libmysqlcapi.a ../../rtr/libpdu.a
