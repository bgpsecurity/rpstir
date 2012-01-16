#
# Makefile for roa libs and test code
#
# $Id: Makefile 1237 2010-09-03 14:24:16Z bkohler $
#

bin_PROGRAMS = roa_test test_val2 test_check_sig sign_roa test_hash make_manifest make_roa 

AM_CFLAGS = -g -I../proto -I../cg/asn -I../cg/asn_gen -I../cg/casn \
	-I../roa-lib -Wall -Wshadow -Wmissing-prototypes -Wmissing-declarations

AM_CPPFLAGS = $(DEPS_CFLAGS)

LDADD = ../proto/librpki.a ../roa-lib/libroa.a ../cg/asn/libasn.a \
	../cg/casn/libcasn.a ../utils/libutils.a

roa_test_SOURCES = roa_test.c
roa_test_LDFLAGS = $(LIBS) -Wl,--allow-multiple-definition
test_val2_SOURCES = test_val2.c
test_val2_LDFLAGS = $(LIBS) -Wl,--allow-multiple-definition
test_check_sig_SOURCES = test_check_sig.c
test_check_sig_LDFLAGS = $(LIBS) -Wl,--allow-multiple-definition
sign_roa_SOURCES = sign_roa.c
sign_roa_LDFLAGS = $(LIBS) -Wl,--allow-multiple-definition
test_hash_SOURCES = test_hash.c
test_hash_LDFLAGS =  $(LIBS) -Wl,--allow-multiple-definition
make_manifest_SOURCES = make_manifest.c
make_manifest_LDFLAGS = $(LIBS) -Wl,--allow-multiple-definition
make_roa_SOURCES = make_roa.c
make_roa_LDFLAGS = $(LIBS) -Wl,--allow-multiple-definition

EXTRA_DIST = *.req *.p15 roa.cnf
