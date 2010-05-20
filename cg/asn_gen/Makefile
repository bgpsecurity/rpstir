#
# Makefile for asn.1 compiler
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
#  Copyright (C) BBN Technologies 2007-2010.  All Rights Reserved.
# 
#  Contributor(s):  Charlie Gardiner
# 
# ***** END LICENSE BLOCK *****

all:	asn_gen

CFLAGS=	-DINTEL -Dconstruct=cconstruct -Ddo_hdr=cdo_hdr -Dasn_constr_id=casn_constr_id -Dasn_hdr_id=casn_hdr_id -DCONSTRAINTS -I. -I../casn -g

asn_gen:	asn_gen.o asn_java.o asn_pproc.o asn_pprocx.o asn_read.o asn_tabulate.o casn_constr.o casn_hdr.o
	$(CC) -o asn_gen $(CFLAGS) -L../casn asn_gen.o asn_java.o asn_pproc.o asn_pprocx.o asn_read.o asn_tabulate.o casn_constr.o casn_hdr.o -lcasn

clean:
	rm -f *.o asn_gen
