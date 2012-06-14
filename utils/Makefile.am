#
# Makefile for utilities convenience library: logging, strings
#
# $Id$
#

SUBDIRS = . tests mysql-c-api

AM_CFLAGS = -g -Wall -Wextra -Werror

noinst_LIBRARIES = libutils.a libutilsdebug.a

libutils_a_SOURCES = \
	bag.c bag.h \
	hashutils.c hashutils.h \
	logging.h \
	logutils.c logutils.h \
	macros.h \
	queue.c queue.h \
	semaphore_compat.c semaphore_compat.h \
	stringutils.c stringutils.h

libutilsdebug_a_SOURCES = $(libutils_a_SOURCES)
libutilsdebug_a_CFLAGS = $(AM_CFLAGS) -DDEBUG
