#
# Makefile for libcasn.a
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
#  Contributor(s):  Charles Gardiner
# 
# ***** END LICENSE BLOCK *****

# --- macros
#CC=gcc
CFLAGS=	-g -I/usr/local/include -I/usr/local/ssl/include -Wall
AR=ar
RANLIB=ranlib

# --- targets
all:    libcasn.a

libcasn.a: *.c
	$(CC) $(CFLAGS) -c -DINTEL $?
	$(AR) -r $@ *.o
	$(RANLIB) $@

clean:
	rm -f *.a *.o

