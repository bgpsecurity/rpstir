#
# $Id$
#
# Makefile for mysql and openssl test programs
#

all:	libapki.a rcli query chaser garbage makeROA

CFLAGS=	-g -I/usr/local/include -I/usr/local/ssl/include -I../roa-utils -I../cg/asn -I../cg/casn -Wall -Wextra -Wshadow -Wmissing-prototypes -Wmissing-declarations -Wmissing-field-initializers -DHAVE_LONG_LONG

# OBSOLETE test program
sqq:	sqq.o Makefile
	gcc -o sqq -g -L/usr/local/lib sqq.o -lmyodbc3 -lrt

# OBSOLETE test program
docert:	docert.o Makefile
	gcc -o docert -g -L/usr/local/ssl/lib docert.o -lssl -lcrypto -ldl

initscm.o:	scm.h scmmain.h
diru.o:	diru.h err.h
sqhl.o:	scm.h scmf.h sqhl.h diru.h myssl.h err.h
sqcon.o:	scm.h scmf.h err.h
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
	gcc -o rcli -g -L/usr/local/ssl/lib -L. rcli.o -lapki -lssl -lcrypto -lmyodbc3 -lrt

query: query.o libapki.a Makefile
	gcc -o query -g -L/usr/local/ssl/lib -L../roa-utils -L../cg/asn -L../cg/casn -L. query.o -lapki -lssl -lcrypto -lmyodbc3 -lrt -lroa -lasn -lcasn

chaser: chaser.o libapki.a Makefile
	gcc -o chaser -g -L/usr/local/ssl/lib -L. chaser.o -lapki -lssl -lcrypto -lmyodbc3 -lrt

garbage: garbage.o libapki.a Makefile
	gcc -o garbage -g -L/usr/local/ssl/lib -L. garbage.o -lapki -lssl -lcrypto -lmyodbc3 -lrt

makeROA: makeROA.o libapki.a Makefile
	gcc -o makeROA -g -L/usr/local/ssl/lib -L../roa-utils -L../cg/asn -L../cg/casn -L. makeROA.o -lapki -lssl -lcrypto -lmyodbc3 -lrt -lroa -lasn -lcasn

clean:
	rm -f rcli query makeROA chaser garbage *.o *.a
