AM_CFLAGS = -g -Wall -Wextra -Werror
AM_CPPFLAGS = $(DEPS_CFLAGS) -I..

LDADD = ../libutilsdebug.a

check_PROGRAMS = bag-test queue-test

bag_test_SOURCES = bag-test.c ../unittest.h
queue_test_SOURCES = queue-test.c ../unittest.h

TESTS = bag-test queue-test
