# Quick and dirty Makefile for certificate verification routines 
#

### PREDEFINES

# pick gcc if you'd rather , and/or do -g instead of -O if debugging
# debugging
# DFLAGS = -DTEST -DDEBUG
DFLAGS = 
CFLAGS =-g -Wall
XFLAGS =        # xtra cflags, set by systype targets
#IFLAGS =-I/usr/local/ssl/include 
#XLIBS =-ldl -L/usr/local/ssl/lib -lcrypto    # xtra libs if necessary?
IFLAGS =
XLIBS =
# -Bstatic for sunos,  -static for gcc, etc.  You want this, trust me.
STATIC =
CC = gcc $(CFLAGS)
LD = $(CC)      # linker; defaults to stripped executables
o = o           # object extension
ALL_OBJS= main.o parse.o socket_stuff.o sig_handler.o usage.o

ALL = rsync_aur

 
### BOGON-CATCHERS

bogus:
	@echo "Usage:  make [options]"

### HARD TARGETS

rsync_aur:	$(ALL_OBJS)
	$(LD) $(DFLAGS) $(XFLAGS) $(STATIC) -o rsync_aur \
	$(ALL_OBJS) $(IFLAGS) $(XLIBS)

main.o :	main.c
	$(CC) $(DFLAGS) $(XFLAGS) $(IFLAGS) $(STATIC) -c main.c

parse.o :	parse.c
	$(CC) $(DFLAGS) $(XFLAGS) $(IFLAGS) $(STATIC) -c parse.c

socket_stuff.o	:	socket_stuff.c
	$(CC) $(DFLAGS) $(XFLAGS) $(IFLAGS) $(STATIC) -c socket_stuff.c

sig_handler.o	:	sig_handler.c
	$(CC) $(DFLAGS) $(XFLAGS) $(IFLAGS) $(STATIC) -c sig_handler.c

usage.o	:	usage.c
	$(CC) $(DFLAGS) $(XFLAGS) $(STATIC) -c usage.c 


### SYSTYPES
generic:
	make -e $(ALL) $(MFLAGS)
	
#LIBS=-lgen

### RANDOM

clean:
	rm -f $(ALL) *.o core

