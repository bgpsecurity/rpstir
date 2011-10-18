#
# Makefile for asn.1 compiler
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

bin_PROGRAMS = asn_gen

AM_CFLAGS= -g -Wall -DINTEL -Dconstruct=cconstruct -Ddo_hdr=cdo_hdr \
	-Dasn_constr_id=casn_constr_id \
	-Dasn_hdr_id=casn_hdr_id -DCONSTRAINTS -I. -I../casn
AM_LDFLAGS=
LDADD = ../casn/libcasn.a

asn_gen_SOURCES = \
	asn_error.h \
	asn_flags.h \
	asn_gen.c \
	asn_gen.h \
	asn.h \
	asn_java.c \
	asn_obj.h \
	asn_pproc.c \
	asn_pprocx.c \
	asn_read.c \
	asn_tabulate.c \
	asn_timedefs.h \
	casn_constr.c \
	casn_hdr.c

asn_gen_LDFLAGS=
