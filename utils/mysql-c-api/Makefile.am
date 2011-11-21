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

AM_CFLAGS = -g -Wall -Wextra
AM_CPPFLAGS = $(DEPS_CFLAGS) -I..

LDADD = ../libutils.a libmysqlcapi.a

noinst_LIBRARIES = libmysqlcapi.a
bin_PROGRAMS = test-driver

libmysqlcapi_a_SOURCES = connect.c ../libutils.a

test_driver_SOURCES = test-driver.c
