#
# Makefile for asn.1 tools
#
# $Id$
#

all:	dump rr

CFLAGS=	-Wall

dump:	dump.o asn.o asn_dump.o util.o asn.h
	$(CC) -o dump -g dump.o asn.o asn_dump.o util.o

rr:	rr.o md2.o asn.o asn.h
	$(CC) -o rr -g rr.o md2.o asn.o

clean:
	rm -f dump rr *.o

