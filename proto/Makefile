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

all:	libapki.a rcli query chaser garbage makeROA

CFLAGS=	-g -I/usr/local/include -I/usr/local/ssl/include -I../roa-utils -I../cg/asn -I../cg/casn -Wall -Wshadow -Wmissing-prototypes -Wmissing-declarations -DHAVE_LONG_LONG

MY_LIBS=	-L/usr/local/ssl/lib -L/usr/local/lib -L. -L../cg/asn -L../cg/casn -L../roa-utils -lapki -lroa -lssl -lcrypto -lasn -lcasn -lmyodbc3 $(LIBXTRA) $(LIBCL) $(LIBDL) $(LIBPTHREAD)

# OBSOLETE test program
#sqq:	sqq.o Makefile
#	$(CC) -o sqq -g -L/usr/local/lib sqq.o -lmyodbc3 -lrt

# OBSOLETE test program
#docert:	docert.o Makefile
#	$(CC) -o docert -g -L/usr/local/ssl/lib docert.o -lssl -lcrypto $(LIBDL)

initscm.o:	scm.h scmmain.h
diru.o:	diru.h err.h
sqhl.o:	scm.h scmf.h sqhl.h diru.h myssl.h err.h
sqcon.o:	scm.h scmf.h diru.h err.h
myssl.o:	myssl.h scm.h scmf.h sqhl.h err.h
err.o:	err.h

rcli.o:	scm.h scmf.h sqhl.h diru.h myssl.h err.h
query.o: scm.h scmf.h err.h myssl.h sqhl.h
chaser.o: scm.h scmf.h sqhl.h err.h
garbage.o:	scm.h scmf.h sqhl.h err.h
makeROA.o:	err.h

libapki.a:	initscm.o myssl.o sqhl.o sqcon.o diru.o err.o
	ar crv libapki.a initscm.o myssl.o sqhl.o sqcon.o diru.o err.o
	ranlib libapki.a

rcli:	rcli.o libapki.a Makefile
	$(CC) -o rcli -g rcli.o $(MY_LIBS)

query: query.o libapki.a Makefile
	$(CC) -o query -g query.o $(MY_LIBS)

chaser: chaser.o libapki.a Makefile
	$(CC) -o chaser -g chaser.o $(MY_LIBS)

garbage: garbage.o libapki.a Makefile
	$(CC) -o garbage -g garbage.o $(MY_LIBS)

makeROA: makeROA.o libapki.a Makefile
	$(CC) -o makeROA -g makeROA.o $(MY_LIBS)

# OBSOLETE test program
#testmem:	testmem.o libapki.a Makefile
#	$(CC) -o testmem -g testmem.o $(MY_LIBS)

clean:
	rm -f rcli query makeROA chaser garbage *.o *.a
