#
# Makefile for rsync_aur
#
# $Id: Makefile 1259 2010-09-14 17:53:17Z bkohler $
#

AM_CFLAGS = -g -Wall -Wshadow -Wmissing-prototypes -Wmissing-declarations

AM_CPPFLAGS = -I../proto -I../cg/casn -I../cg/asn -I../roa-lib -I../proto \
	-I../utils

LDADD = ../roa-lib/libroa.a \
	../cg/asn/libasn.a \
	../cg/casn/libcasn.a \
	../utils/libutils.a

bin_PROGRAMS = rsync_aur rsync_listener

EXTRA_DIST = \
	AUR.readme \
	rsync_test.config \
	test.log

rsync_aur_SOURCES = main.c main.h parse.c socket_stuff.c sig_handler.c \
	csapp.c csapp.h usage.c usage.h socket_stuff.h parse.h sig_handler.h

rsync_listener_SOURCES = rsync_listener.c csapp.h rsync_listener.h csapp.c
