#
# Makefile for libcasn.a
#
# $Id$
#

# --- macros
CC=gcc
CFLAGS=	-g -I/usr/local/include -I/usr/local/ssl/include -Wall
AR=ar
RANLIB=ranlib

# --- targets
all:    libcasn.a

libcasn.a: *.c
	$(CC) $(CFLAGS) -c -DINTEL $?
	$(AR) -r $@ *.o
	$(RANLIB) $@

clean:
	rm -f libcasn.a *.o

