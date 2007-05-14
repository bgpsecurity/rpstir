
#
# $Id$
#
# Makefile for roa_test
#

# --- macros
CC=gcc
CFLAGS=	-g -I/usr/local/include -I/usr/local/ssl/include -I../cg/asn -I../cg/asn_gen -I../cg/casn -I../proto -Wall
TEST_OBJECTS= roa_test.o
ASN_DIR= ../cg/asn
CASN_DIR= ../cg/casn
LOCAL_LIBS= -L. -L$(ASN_DIR) -L$(CASN_DIR) -lroa -lasn -lcasn
LIBS= -L/usr/local/ssl/lib -lcrypto
AR= ar
RANLIB= ranlib

# --- targets
all:    libroa.a roa_test

b64:	b64.o
	$(CC) $(CFLAGS) -c b64.c
	$(CC) -o $@ b64.o

#roa_test: roa_test.o roa_serialize.o Makefile
#	gcc -o roa_test -g -L/usr/local/ssl/lib roa_test.o roa_validate.o roa.o

roa_test:   $(TEST_OBJECTS) 
	$(CC) -o $@ $(TEST_OBJECTS) $(LOCAL_LIBS)

roa_test.o: roa_test.c roa_utils.h
	$(CC) $(CFLAGS) -c roa_test.c

roa_validate.o: roa_validate.c roa_utils.h
	$(CC) $(CFLAGS) -c roa_validate.c

roa_create.o: roa_create.c roa_utils.h
	$(CC) $(CFLAGS) -c roa_create.c

roa_general.o: roa_general.c roa_utils.h
	$(CC) $(CFLAGS) -c roa_general.c

roa_serialize.o: roa_serialize.c roa_utils.h
	$(CC) $(CFLAGS) -c roa_serialize.c

libroa.a:	roa_validate.o roa_create.o roa_general.o roa_serialize.o
	ar crv libroa.a roa_validate.o roa_create.o roa_general.o roa_serialize.o
	ranlib libroa.a

clean:
	rm -f roa_test *.a *.o

clean2:
	rm -f *.pem *.der *.txt
