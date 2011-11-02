AM_CFLAGS = -g -Wall -Wextra -Werror
AM_CPPFLAGS = $(DEPS_CFLAGS) -I..

LDADD = ../libutils.a

noinst_PROGRAMS = queue-test

queue_test_SOURCES = queue-test.c

test: queue-test
	./queue-test
