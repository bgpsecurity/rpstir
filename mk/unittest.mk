check_PROGRAMS += tests/unittest-test

tests_unittest_test_SOURCES = \
	tests/unittest-test.c \
	tests/unittest.h

tests_unittest_test_CFLAGS = \
	$(CFLAGS_STRICT)

TESTS += tests/unittest-test
