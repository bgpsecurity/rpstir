#
# Makefile for libcasn.a
#
# $Id: Makefile 1135 2010-05-24 13:17:17Z achi $
#

AM_CFLAGS = -g -Wall -DINTEL
AM_CPPFLAGS = -I../../utils

noinst_LIBRARIES = libcasn.a

libcasn_a_SOURCES = casn.c casn_bit.c casn_bits.c casn_copy_diff.c casn_dump.c \
	casn_error.c casn_file_ops.c casn_num.c casn_objid.c casn_other.c \
	casn_real.c casn_time.c casn.h asn.h asn_flags.h
libcasn_a_DEPENDENCIES = casn.h
