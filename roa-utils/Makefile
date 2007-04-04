#
# $Id$
#
# Makefile for roa_test
#

# --- macros
CC=gcc
CFLAGS=	-g -I/usr/local/include -I/usr/local/ssl/include -I../cg/asn -I../cg/asn_gen -I../cg/casn -Wall
TEST_OBJECTS= roa_test.o roa_serialize.o roa_create.o roa_general.o roa.o name.o extensions.o certificate.o Algorithms.o orname.o
CASN_LIB= -L../cg/casn -lcasn
LIBS = -L/usr/local/ssl/lib -lcrypto

# --- targets
all:    roa_test

#roa_test: roa_test.o roa_serialize.o Makefile
#	gcc -o roa_test -g -L/usr/local/ssl/lib roa_test.o roa_validate.o roa.o

roa_test:   $(TEST_OBJECTS) 
	$(CC) -o $@ $(TEST_OBJECTS) $(CASN_LIB)

roa_test.o: roa_test.c roa_utils.h
	$(CC) $(CFLAGS) -c roa_test.c

roa_validate.o: roa_validate.c roa_utils.h
	$(CC) $(CFLAGS) -c roa_validate.c

roa_create.o: roa_create.c roa_utils.h
	$(CC) $(CFLAGS) -c roa_create.c

roa_general.o: roa_general.c roa_utils.h
	$(CC) $(CFLAGS) -c roa_general.c

roa.o: ../cg/asn/roa.c ../cg/asn/extensions.c ../cg/asn/name.c ../cg/asn/certificate.c ../cg/asn/Algorithms.c ../cg/asn/orname.c
	$(CC) $(CFLAGS) -c $?

clean:
	rm -f roa_test *.o
