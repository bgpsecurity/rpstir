AM_CFLAGS = -g -Wall -Wextra -Werror
AM_CPPFLAGS = $(DEPS_CFLAGS) -I..

LDADD = ../libutilsdebug.a

check_PROGRAMS = \
	bag-test \
	queue-test \
	stringutils-test \
	unittest-test

bag_test_SOURCES = bag-test.c ../unittest.h
queue_test_SOURCES = queue-test.c ../unittest.h
stringutils_test_SOURCES = stringutils-test.c ../unittest.h
unittest_test_SOURCES = unittest-test.c ../unittest.h

TESTS_ENVIRONMENT = $(top_srcdir)/utils/run_with_tool.sh
TESTS = $(check_PROGRAMS)
