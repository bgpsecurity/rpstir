all:	dump rr

CFLAGS=	-Wall

dump:	dump.o asn.o asn_dump.o util.o asn.h
	gcc -o dump -g dump.o asn.o asn_dump.o util.o

rr:	rr.o md2.o asn.o asn.h
	gcc -o rr -g rr.o md2.o asn.o

clean:
	rm -f dump rr *.o

