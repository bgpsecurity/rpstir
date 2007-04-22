#
# $Id$
#
# Makefile for mysql and openssl test programs
#

all:	rcli query chaser garbage makeROA

CFLAGS=	-g -I/usr/local/include -I/usr/local/ssl/include -I../roa-utils -I../cg/asn -I../cg/casn -Wall -Wextra -Wshadow -Wmissing-prototypes -Wmissing-declarations -Wmissing-field-initializers -DHAVE_LONG_LONG

sqq:	sqq.o Makefile
	gcc -o sqq -g -L/usr/local/lib sqq.o -lmyodbc3 -lrt

docert:	docert.o Makefile
	gcc -o docert -g -L/usr/local/ssl/lib docert.o -lssl -lcrypto -ldl

diru.o:	diru.h
sqhl.o:	sqhl.h myssl.h
rcli.o:	scm.h scmf.h sqhl.h myssl.h diru.h
myssl.o:	myssl.h
query.o: scm.h scmf.h err.h
chaser.o: scm.h scmf.h err.h
err.o:	err.h

rcli:	rcli.o initscm.o myssl.o sqhl.o sqcon.o diru.o err.o Makefile
	gcc -o rcli -g -L/usr/local/ssl/lib rcli.o initscm.o myssl.o sqhl.o sqcon.o diru.o err.o -lssl -lcrypto -lmyodbc3 -lrt

query: query.o initscm.o myssl.o sqhl.o sqcon.o diru.o Makefile
	gcc -o query -g -L/usr/local/ssl/lib -L../roa-utils -L../cg/casn query.o initscm.o myssl.o sqhl.o sqcon.o diru.o -lssl -lcrypto -lmyodbc3 -lrt -lroa -lcasn

makeROA: makeROA.o initscm.o myssl.o sqhl.o sqcon.o diru.o Makefile
	gcc -o makeROA -g -L/usr/local/ssl/lib -L../roa-utils -L../cg/casn makeROA.o initscm.o myssl.o sqhl.o sqcon.o diru.o -lssl -lcrypto -lmyodbc3 -lrt -lroa -lcasn

chaser: chaser.o initscm.o myssl.o sqhl.o sqcon.o diru.o Makefile
	gcc -o chaser -g -L/usr/local/ssl/lib chaser.o initscm.o myssl.o sqhl.o sqcon.o diru.o -lssl -lcrypto -lmyodbc3 -lrt

garbage: garbage.o initscm.o myssl.o sqhl.o sqcon.o diru.o Makefile
	gcc -o garbage -g -L/usr/local/ssl/lib garbage.o initscm.o myssl.o sqhl.o sqcon.o diru.o -lssl -lcrypto -lmyodbc3 -lrt

clean:
	rm -f rcli query makeROA chaser garbage sqq docert initscm *.o
