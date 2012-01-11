#
# Makefile for a MySQL utility using the C API
#

#SUBDIRS = .

AM_CFLAGS = -g -Wall -Wextra -Werror
AM_CPPFLAGS = $(DEPS_CFLAGS) -I.. -I../../rtr

noinst_LIBRARIES = libmysqlcapi.a

libmysqlcapi_a_SOURCES = \
  client-chaser.c client-chaser.h \
	connect.c connect.h \
	db-internal.h \
	prep-stmt.c prep-stmt.h \
	rtr.c rtr.h \
	util.c util.h
