AM_CFLAGS = -g -Wall -Wextra -Werror
AM_CPPFLAGS = $(DEPS_CFLAGS) -I..

LDADD = ../libutilsdebug.a

check_PROGRAMS = unittest-test queue-test

unittest_test_SOURCES = unittest-test.c ../unittest.h

queue_test_SOURCES = queue-test.c ../unittest.h

TESTS = unittest-test queue-test
