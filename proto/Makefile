#
# $Id$
#
# Makefile for mysql and openssl test programs
#

all:	sqq docert

CFLAGS=	-g -I/usr/local/include -I/usr/local/ssl/include

sqq:	sqq.o
	gcc -o sqq -g -L/usr/local/lib sqq.o -lmyodbc3 -lrt

docert:	docert.o
	gcc -o docert -g -L/usr/local/ssl/lib docert.o -lssl -lcrypto -ldl

