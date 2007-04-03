#
# $Id$
#
# Makefile for mysql and openssl test programs
#

all:	sqq docert rcli #initscm

CFLAGS=	-g -I/usr/local/include -I/usr/local/ssl/include -Wall -Wextra -Wshadow -Wmissing-prototypes -Wmissing-declarations -Wmissing-field-initializers -DHAVE_LONG_LONG

sqq:	sqq.o Makefile
	gcc -o sqq -g -L/usr/local/lib sqq.o -lmyodbc3 -lrt

docert:	docert.o Makefile
	gcc -o docert -g -L/usr/local/ssl/lib docert.o -lssl -lcrypto -ldl

initscm:	initscm.o Makefile
	gcc -o initscm -g -L/usr/local/ssl/lib initscm.o

initscm.o:	scm.h scmmain.h Makefile
diru.o:	diru.h
sqhl.o:	sqhl.h myssl.h
rcli.o:	scm.h scmf.h sqhl.h myssl.h diru.h
myssl.o:	myssl.h
doQuery.o: scm.h scmf.h err.h
err.o:	err.h

rcli:	rcli.o initscm.o myssl.o sqhl.o sqcon.o diru.o err.o Makefile
	gcc -o rcli -g -L/usr/local/ssl/lib rcli.o initscm.o myssl.o sqhl.o sqcon.o diru.o err.o -lssl -lcrypto -lmyodbc3 -lrt

doQuery: doQuery.o initscm.o myssl.o sqhl.o sqcon.o diru.o Makefile
	gcc -o doQuery -g -L/usr/local/ssl/lib doQuery.o initscm.o myssl.o sqhl.o sqcon.o diru.o -lssl -lcrypto -lmyodbc3 -lrt

clean:
	rm -f rcli sqq docert initscm *.o
