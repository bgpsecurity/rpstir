#
# Makefile for roa libs
#
# $Id: Makefile 527 2008-06-17 15:02:18Z csmall $
#

AM_CFLAGS = -g -Wall -I../proto -I../cg/asn -I../cg/asn_gen -I../cg/casn \
	-I../utils -Wshadow -Wmissing-prototypes -Wmissing-declarations -DANYSKI

noinst_LIBRARIES = libroa.a

libroa_a_SOURCES = roa_validate.c roa_utils.h roa_create.c roa_general.c signCMS.c roa_serialize.c
