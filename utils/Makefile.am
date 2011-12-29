#
# Makefile for utilities convenience library: logging, strings
#
# $Id$
#

SUBDIRS = . tests

AM_CFLAGS = -g -Wall

noinst_LIBRARIES = libutils.a libutilsdebug.a

libutils_a_SOURCES = logutils.h logutils.c macros.h \
	stringutils.h stringutils.c hash_utils.c \
	queue.c queue.h \
	semaphore_compat.c semaphore_compat.h

libutilsdebug_a_SOURCES = $(libutils_a_SOURCES)
libutilsdebug_a_CFLAGS = $(AM_CFLAGS) -DDEBUG
