#
# Makefile for rsync_aur
#
# $Id: Makefile 1259 2010-09-14 17:53:17Z bkohler $
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

AM_CFLAGS = -g -Wall -Wshadow -Wmissing-prototypes -Wmissing-declarations

AM_CPPFLAGS = -I../proto -I../cg/casn -I../cg/asn -I../roa-lib -I../proto \
	-I../utils

LDADD = ../roa-lib/libroa.a ../cg/asn/libasn.a ../cg/casn/libcasn.a \
	../utils/libutils.a

bin_PROGRAMS = rsync_aur rsync_listener

rsync_aur_SOURCES = main.c main.h parse.c socket_stuff.c sig_handler.c \
	csapp.c csapp.h usage.c usage.h socket_stuff.h parse.h sig_handler.h

rsync_listener_SOURCES = rsync_listener.c csapp.h rsync_listener.h csapp.c
rsync_listener_LDFLAGS = -lpthread
