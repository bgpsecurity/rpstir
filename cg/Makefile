#
# Makefile for all asn.1 libs and tools
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
#  Contributor(s):  Mark Reynolds
# 
# ***** END LICENSE BLOCK *****

DIRS=casn asn_gen asn tools

all:	
	for DIR in $(DIRS); do \
		(cd $$DIR && make all \
			LIBCL="$(LIBCL)" \
			LIBCRYPTO="$(LIBCRYPTO)" \
			LIBDL="$(LIBDL)" \
			LIBODBC="$(LIBODBC)" \
			LIBPTHREAD="$(LIBPTHREAD)" \
			LIBXTRA="$(LIBXTRA)" \
			CLINCLUDES="$(CLINCLUDES)" \
			MYSQLINCLUDES="$(MYSQLINCLUDES)" \
			ODBCINCLUDES="$(ODBCINCLUDES)" \
			SSLINCLUDES="$(SSLINCLUDES)" ) ;\
	done

clean:
	for DIR in $(DIRS); do \
		(cd $$DIR && make clean );\
	done
