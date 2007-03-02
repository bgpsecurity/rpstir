# Quick and dirty Makefile for certificate verification routines 
#

### PREDEFINES

# pick gcc if you'd rather , and/or do -g instead of -O if debugging
# debugging
# DFLAGS = -DTEST -DDEBUG
DFLAGS = 
CFLAGS =-g -Wall
XFLAGS =        # xtra cflags, set by systype targets
IFLAGS =-I/usr/local/ssl/include 
XLIBS =-ldl -L/usr/local/ssl/lib -lcrypto    # xtra libs if necessary?
# -Bstatic for sunos,  -static for gcc, etc.  You want this, trust me.
STATIC =
CC = gcc $(CFLAGS)
LD = $(CC)      # linker; defaults to stripped executables
o = o           # object extension
ALL_OBJS= verify_cert.o stubs.o stub_main.o usage.o

ALL = verify_stub_test

 
### BOGON-CATCHERS

bogus:
	@echo "Usage:  make [options]"

### HARD TARGETS

verify_stub_test:	$(ALL_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) $(STATIC) -o verify_stub_test \
	$(ALL_OBJS) $(IFLAGS) $(XLIBS)

verify_cert.o :	verify_cert.c
	$(CC) $(DFLAGS) $(XFLAGS) $(IFLAGS) $(STATIC) -c verify_cert.c

stubs.o :	stubs.c
	$(CC) $(DFLAGS) $(XFLAGS) $(IFLAGS) $(STATIC) -c stubs.c

stub_main.o :	stub_main.c
	$(CC) $(DFLAGS) $(XFLAGS) $(IFLAGS) $(STATIC) -c stub_main.c

usage.o :	usage.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c usage.c 


### SYSTYPES
generic:
	make -e $(ALL) $(MFLAGS)
	
#LIBS=-lgen

### RANDOM

clean:
	rm -f $(ALL) *.o core

