
#
# $Id$
#
# Makefile for roa_test
#

# --- macros
CC=gcc
CFLAGS=	-g -I/usr/local/include -I/usr/local/ssl/include -I../cg/asn -I../cg/asn_gen -I../cg/casn -Wall
TEST_OBJECTS= roa_test.o
LIB_OBJECTS= roa_serialize.o roa_validate.o roa_create.o roa_general.o \
	roa.o name.o extensions.o certificate.o Algorithms.o orname.o
ASN_DIR= ../cg/asn
CASN_DIR= ../cg/casn
LOCAL_LIBS= -L. -lroa -L$(CASN_DIR) -lcasn
LIBS= -L/usr/local/ssl/lib -lcrypto
AR= ar
RANLIB= ranlib

# --- targets
all:    libroa.a libcasn.a roa_test

b64:	b64.o
	$(CC) $(CFLAGS) -c b64.c
	$(CC) -o $@ b64.o

#roa_test: roa_test.o roa_serialize.o Makefile
#	gcc -o roa_test -g -L/usr/local/ssl/lib roa_test.o roa_validate.o roa.o

roa_test:   $(TEST_OBJECTS) 
	$(CC) -o $@ $(TEST_OBJECTS) $(LOCAL_LIBS)

libcasn.a:
	(cd $(CASN_DIR); make)

libroa.a:  $(LIB_OBJECTS)
	$(AR) -r $@ $?
	$(RANLIB) $@

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

roa.o: $(ASN_DIR)/roa.c $(ASN_DIR)/extensions.c $(ASN_DIR)/name.c $(ASN_DIR)/certificate.c $(ASN_DIR)/Algorithms.c $(ASN_DIR)/orname.c
	$(CC) $(CFLAGS) -c $?

clean:
	(cd $(CASN_DIR); make clean)
	rm -f roa_test *.a *.o

clean2:
	rm -f *.pem *.der *.txt
