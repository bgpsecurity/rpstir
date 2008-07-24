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
CFLAGS=	-g -Wall -DINTEL
AR=ar
RANLIB=ranlib

# --- targets
all:    libcasn.a

CFILES=casn.c casn_bit.c casn_bits.c casn_copy_diff.c casn_dump.c \
	casn_error.c casn_file_ops.c casn_num.c casn_objid.c casn_other.c \
	casn_real.c casn_time.c
OFILES=$(CFILES:.c=.o)

$(OFILES): casn.h

libcasn.a: $(OFILES)
	$(AR) -r $@ $(OFILES)
	$(RANLIB) $@

clean:
	rm -f *.a *.o

