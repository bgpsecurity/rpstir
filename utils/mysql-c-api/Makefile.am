#
# Makefile for a MySQL utility using the C API
#

#SUBDIRS = .

AM_CFLAGS = -g -Wall -Wextra -Werror
AM_CPPFLAGS = $(DEPS_CFLAGS) -I.. -I../../rtr

noinst_LIBRARIES = libmysqlcapi.a
check_PROGRAMS = test-driver

libmysqlcapi_a_SOURCES = \
	connect.c connect.h \
	db-internal.h \
	prep-stmt.c prep-stmt.h \
	rtr.c rtr.h \
	util.c util.h

test_driver_SOURCES = test-driver.c test-driver.h 
test_driver_LDADD = ../libutils.a libmysqlcapi.a ../../rtr/libpdu.a
