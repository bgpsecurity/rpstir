#
# Makefile for rsync_aur
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
#  Copyright (C) Raytheon BBN Technologies Corp. 2007.  All Rights Reserved.
# 
#  Contributor(s):  Peiter "Mudge" Zatko
# 
# ***** END LICENSE BLOCK *****

### PREDEFINES

# pick gcc if you'd rather , and/or do -g instead of -O if debugging
# debugging
# DFLAGS = -DTEST -DDEBUG
CC = gcc
DFLAGS = 
CFLAGS=-I../proto -I$(CLINCLUDES) -I$(SSLINCLUDES) \
	-g -Wall -Wshadow -Wmissing-prototypes -Wmissing-declarations
XFLAGS =        # xtra cflags, set by systype targets
IFLAGS =-I$(SSLINCLUDES) -I../cg/casn -I../cg/asn -I../roa-lib -I../proto
XLIBS = ../roa-lib/libroa.a ../cg/asn/libasn.a  ../cg/casn/libcasn.a
XLIBS_SYS = $(LIBCL) $(LIBDL) $(LIBPTHREAD)
# -Bstatic for sunos,  -static for gcc, etc.  You want this, trust me.
STATIC =
CC += $(CFLAGS)
LD = $(CC)      # linker; defaults to stripped executables
o = o           # object extension
ALL_OBJS= main.o parse.o socket_stuff.o sig_handler.o usage.o

ALL = rsync_aur

all:	$(ALL)

### BOGON-CATCHERS

bogus:
	@echo "Usage:  make [options]"

### HARD TARGETS

rsync_aur:	$(ALL_OBJS) $(XLIBS)
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -o rsync_aur \
	$(ALL_OBJS) $(IFLAGS) $(XLIBS) $(XLIBS_SYS)

main.o :	main.c main.h 
	$(CC) $(DFLAGS) $(XFLAGS) $(IFLAGS) $(STATIC) -c main.c

parse.o :	parse.c main.h
	$(CC) $(DFLAGS) $(XFLAGS) $(IFLAGS) $(STATIC) -c parse.c

socket_stuff.o	:	socket_stuff.c main.h
	$(CC) $(DFLAGS) $(XFLAGS) $(IFLAGS) $(STATIC) -c socket_stuff.c

sig_handler.o	:	sig_handler.c main.h
	$(CC) $(DFLAGS) $(XFLAGS) $(IFLAGS) $(STATIC) -c sig_handler.c

usage.o	:	usage.c main.h
	$(CC) $(DFLAGS) $(XFLAGS) $(IFLAGS) $(STATIC) -c usage.c 

main.h:	usage.h socket_stuff.h parse.h sig_handler.h

### SYSTYPES
generic:
	$(MAKE) -e $(ALL) $(MFLAGS)

#LIBS=-lgen

### RANDOM

clean:
	rm -f $(ALL) *.o core

