#
# Makefile for all asn.1 libs and tools
#
# $Id$
#
# ***** BEGIN LICENSE BLOCK *****
#  
#  BBN Address and AS Number PKI Database/repository software
#  Verison 1.0
#  
#  US government users are permitted unrestricted rights as
#  defined in the FAR.  
# 
#  This software is distributed on an "AS IS" basis, WITHOUT
#  WARRANTY OF ANY KIND, either express or implied.
# 
#  Copyright (C) BBN Technologies 2007.  All Rights Reserved.
# 
#  Contributor(s):  Mark Reynolds
# 
# ***** END LICENSE BLOCK *****

all:	casn.dir asn_gen.dir asn.dir tools.dir

casn.dir:
	cd casn && make all

asn_gen.dir:
	cd asn_gen && make all

asn.dir:
	cd asn && make all

tools.dir:
	cd tools && make all

clean:
	cd casn && make clean
	cd asn_gen && make clean
	cd asn && make clean
	cd tools && make clean
