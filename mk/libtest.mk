# currently it's just a header, but it could be expanded to contain C code in the future
LDADD_LIBTEST =

EXTRA_DIST += \
	lib/test/unittest.h


check_PROGRAMS += lib/test/tests/unittest-test

TESTS += lib/test/tests/unittest-test
