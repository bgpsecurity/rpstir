#
# Makefile for libcasn.a
#
# $Id: Makefile 1135 2010-05-24 13:17:17Z achi $
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
#  Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.  All Rights Reserved.
# 
#  Contributor(s):  Brenton Kohler
# 
# ***** END LICENSE BLOCK *****

AM_CFLAGS = -g -Wall -DINTEL
AM_CPPFLAGS = -I../../utils

noinst_LIBRARIES = libcasn.a

libcasn_a_SOURCES = casn.c casn_bit.c casn_bits.c casn_copy_diff.c casn_dump.c \
	casn_error.c casn_file_ops.c casn_num.c casn_objid.c casn_other.c \
	casn_real.c casn_time.c casn.h asn.h asn_error.h asn_flags.h
libcasn_a_DEPENDENCIES = casn.h
