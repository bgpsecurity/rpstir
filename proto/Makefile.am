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

AM_CFLAGS= -g -Wall -I../roa-lib -I../roa-utils -I../cg/asn -I../cg/casn -I. \
	-Wshadow -Wmissing-prototypes -Wmissing-declarations \
	-DHAVE_LONG_LONG

AM_LDFLAGS = $(LIBS)

lib_rpki_files = scm.h scmmain.h diru.h err.h scmf.h sqhl.h myssl.h \
		initscm.c myssl.c sqhl.c sqcon.c diru.c err.c \
		querySupport.c rpwork.c conversion.c rpcommon.c rpwork.h

noinst_LIBRARIES = librpki.a
bin_PROGRAMS = rcli query chaser garbage makeROA proofreader testrpwork

local_libs = -L../cg/asn -lasn -L../cg/casn -lcasn -L. -lrpki -L../roa-lib -lroa
LDADD = $(local_libs)
AM_CPPFLAGS = $(DEPS_CFLAGS)

librpki_a_SOURCES = ${lib_rpki_files} 

rcli_SOURCES = rcli.c $(lib_rpki_files)
rcli_LDFLAGS = $(LIBS) -Wl,--allow-multiple-definition
query_SOURCES = query.c $(lib_rpki_files)
query_LDFLAGS = $(LIBS) -Wl,--allow-multiple-definition
chaser_SOURCES = chaser.c $(lib_rpki_files)
chaser_LDFLAGS = $(LIBS) -Wl,--allow-multiple-definition
garbage_SOURCES = garbage.c $(lib_rpki_files)
garbage_LDFLAGS = $(LIBS) -Wl,--allow-multiple-definition
makeROA_SOURCES = makeROA.c $(lib_rpki_files)
makeROA_LDFLAGS = $(LIBS) -Wl,--allow-multiple-definition
proofreader_SOURCES = proofreader.c $(lib_rpki_files)
proofreader_LDFLAGS = $(LIBS) -Wl,--allow-multiple-definition
testrpwork_SOURCES = testrpwork.c $(lib_rpki_files)
testrpwork_LDFLAGS = $(LIBS) -Wl,--allow-multiple-definition

