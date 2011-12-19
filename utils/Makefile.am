#
# Makefile for utilities convenience library: logging, strings
#
# $Id$
#

SUBDIRS = . tests mysql-c-api

AM_CFLAGS = -g -Wall -Wextra -Werror

noinst_LIBRARIES = libutils.a libutilsdebug.a

libutils_a_SOURCES = logutils.h logutils.c macros.h \
	stringutils.h stringutils.c hash_utils.c \
	semaphore_compat.c semaphore_compat.h \
	bag.c bag.h \
	queue.c queue.h \
	logging.h

libutilsdebug_a_SOURCES = $(libutils_a_SOURCES)
libutilsdebug_a_CFLAGS = $(AM_CFLAGS) -DDEBUG
