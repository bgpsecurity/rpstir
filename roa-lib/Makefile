#
# Makefile for roa libs
#
# $Id: Makefile 527 2008-06-17 15:02:18Z csmall $
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
#  Contributor(s):  Joshua Gruenspecht, Mark Reynolds
# 
# ***** END LICENSE BLOCK *****

# --- macros
ifneq ($(CLINCLUDES),)
  CFLAGS += -I$(CLINCLUDES)
endif

ifneq ($(SSLINCLUDES),)
  CFLAGS += -I$(SSLINCLUDES)
endif

CFLAGS += -I../cg/asn -I../cg/asn_gen -I../cg/casn -I../proto \
	-g -Wall -Wshadow -Wmissing-prototypes -Wmissing-declarations -DANYSKI

# --- targets
all:    libroa.a

roa_validate.o: roa_validate.c roa_utils.h
roa_create.o: roa_create.c roa_utils.h 
roa_general.o: roa_general.c roa_utils.h
roa_serialize.o: roa_serialize.c roa_utils.h
signCMS.o: signCMS.c

libroa.a: roa_validate.o roa_create.o roa_general.o roa_serialize.o roa_utils.h signCMS.o
	ar crv libroa.a roa_validate.o roa_create.o roa_general.o roa_serialize.o signCMS.o
	ranlib libroa.a

clean:
	rm -f libroa.a *.o

clean2:
	rm -f *.pem *.der *.txt
