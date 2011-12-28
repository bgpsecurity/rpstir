AM_CFLAGS = -g -Wall -Wextra -Werror
AM_CPPFLAGS = $(DEPS_CFLAGS) -I..

LDADD = ../libutilsdebug.a

check_PROGRAMS = \
	unittest-test \
	bag-test \
	queue-test

unittest_test_SOURCES = unittest-test.c ../unittest.h
bag_test_SOURCES = bag-test.c ../unittest.h
queue_test_SOURCES = queue-test.c ../unittest.h

TESTS = $(check_PROGRAMS)
