#
# Makefile for asn.1 compiler
#
# $Id: Makefile 1135 2010-05-24 13:17:17Z achi $
#

bin_PROGRAMS = asn_gen

AM_CFLAGS= -g -Wall -DINTEL -Dconstruct=cconstruct -Ddo_hdr=cdo_hdr \
	-Dasn_constr_id=casn_constr_id \
	-Dasn_hdr_id=casn_hdr_id -DCONSTRAINTS -I.
AM_LDFLAGS=

asn_gen_SOURCES = \
	asn_flags.h \
	asn_gen.c \
	asn_gen.h \
	asn.h \
	asn_java.c \
	asn_obj.h \
	asn_pproc.c \
	asn_pprocx.c \
	asn_read.c \
	asn_tabulate.c \
	asn_timedefs.h \
	casn_constr.c \
	casn_hdr.c

asn_gen_LDFLAGS=
