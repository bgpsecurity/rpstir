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
bin_PROGRAMS = create_object gen_hash

AM_CFLAGS = -g -Wall -DDEBUG -I../../cg/asn -I../../cg/asn_gen -I../../cg/casn

AM_LDFLAGS = $(LIBS)
LDADD = ../../proto/librpki.a ../../roa-lib/libroa.a ../../cg/asn/libasn.a ../../cg/casn/libcasn.a

create_object_SOURCES = create_object.c create_object.h create_cert.h \
	create_manifest.c create_roa.h create_utils.h obj_err.h create_crl.c \
	create_cert.c create_manifest.h create_roa.c create_utils.c \
	sign_object.c

gen_hash_SOURCES = gen_hash.c
