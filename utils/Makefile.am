#
# Makefile for utilities convenience library: logging, strings
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
#  Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.
#  All Rights Reserved.
# 
#  Contributor(s):  Andrew Chi
# 
# ***** END LICENSE BLOCK *****

SUBDIRS = . tests mysql-c-api

AM_CFLAGS = -g -Wall -Wextra -Werror

noinst_LIBRARIES = libutils.a libutilsdebug.a

libutils_a_SOURCES = logutils.h logutils.c macros.h \
	stringutils.h stringutils.c hash_utils.c \
	bag.c bag.h \
	queue.c queue.h \
	logging.h

libutilsdebug_a_SOURCES = $(libutils_a_SOURCES)
libutilsdebug_a_CFLAGS = $(AM_CFLAGS) -DDEBUG
