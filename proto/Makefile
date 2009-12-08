#
# $Id$
#
# Makefile for mysql and openssl test programs
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

all:	librpki.a rcli query chaser garbage makeROA proofreader 

ifneq ($(MYSQLINCLUDES),)
  CFLAGS += -I$(MYSQLINCLUDES)
endif

ifneq ($(SSLINCLUDES),)
  CFLAGS += -I$(SSLINCLUDES)
endif

CFLAGS += -I../roa-lib -I../cg/asn -I../cg/casn \
	-g -Wall -Wshadow -Wmissing-prototypes -Wmissing-declarations \
	-DHAVE_LONG_LONG

LOCAL_LIBS=./librpki.a ../roa-lib/libroa.a \
	../cg/asn/libasn.a ../cg/casn/libcasn.a

#LIBS=$(LIBSSL) $(LIBCRYPTO) $(LIBCL) \
#     $(LIBODBC) $(LIBXTRA) $(LIBDL) $(LIBPTHREAD)
LIBS=$(LIBSSL) $(LIBCL) $(LIBCRYPTO) \
     $(LIBODBC) $(LIBXTRA) $(LIBDL) $(LIBPTHREAD)


initscm.o:	scm.h scmmain.h
diru.o:	diru.h err.h
sqhl.o:	scm.h scmf.h sqhl.h diru.h myssl.h err.h
sqcon.o:	scm.h scmf.h diru.h err.h
myssl.o:	myssl.h scm.h scmf.h sqhl.h err.h
err.o:	err.h

rcli.o:	scm.h scmf.h sqhl.h diru.h myssl.h err.h
query.o: scm.h scmf.h err.h myssl.h sqhl.h querySupport.h
querySupport.o: scm.h scmf.h err.h sqhl.h querySupport.h
chaser.o: scm.h scmf.h sqhl.h err.h
garbage.o:	scm.h scmf.h sqhl.h err.h
makeROA.o:	err.h
proofreader.o:	err.h conversion.h
conversion.o:	err.h conversion.h
rpwork.o:	err.h conversion.h rpwork.c

librpki.a:	initscm.o myssl.o sqhl.o sqcon.o diru.o err.o querySupport.o
	ar crv librpki.a initscm.o myssl.o sqhl.o sqcon.o diru.o err.o querySupport.o
	ranlib librpki.a

rcli:	rcli.o librpki.a $(LOCAL_LIBS) Makefile
	$(CC) -o rcli -g rcli.o $(LOCAL_LIBS) $(LIBS) $(LOCAL_LIBS)

query: query.o librpki.a $(LOCAL_LIBS) Makefile
	$(CC) -o query -g query.o $(LOCAL_LIBS) $(LIBS)

chaser: chaser.o librpki.a $(LOCAL_LIBS) Makefile
	$(CC) -o chaser -g chaser.o $(LOCAL_LIBS) $(LIBS)

garbage: garbage.o librpki.a $(LOCAL_LIBS) Makefile
	$(CC) -o garbage -g garbage.o $(LOCAL_LIBS) $(LIBS)

makeROA: makeROA.o librpki.a $(LOCAL_LIBS) Makefile
	$(CC) -o makeROA -g makeROA.o $(LOCAL_LIBS) $(LIBS)

proofreader: proofreader.o conversion.o librpki.a $(LOCAL_LIBS) Makefile
	$(CC) -o proofreader -g proofreader.o conversion.o $(LOCAL_LIBS) $(LIBS)

clean:
	rm -f rcli query makeROA chaser garbage *.o *.a
