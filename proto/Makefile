#
# $Id$
#
# Makefile for mysql and openssl test programs
#

all:	sqq docert rcli #initscm

CFLAGS=	-g -I/usr/local/include -I/usr/local/ssl/include

sqq:	sqq.o Makefile
	gcc -o sqq -g -L/usr/local/lib sqq.o -lmyodbc3 -lrt

docert:	docert.o Makefile
	gcc -o docert -g -L/usr/local/ssl/lib docert.o -lssl -lcrypto -ldl

initscm:	initscm.o Makefile
	gcc -o initscm -g -L/usr/local/ssl/lib initscm.o

initscm.o:	scm.h scmmain.h Makefile

rcli:	rcli.o initscm.o Makefile
	gcc -o rcli -g -L/usr/local/ssl/lib rcli.o initscm.o

clean:
	rm -f sqq docert initscm *.o
