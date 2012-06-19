noinst_LIBRARIES += lib/util/libutil.a

lib_util_libutil_a_SOURCES = \
	lib/util/bag.c \
	lib/util/bag.h \
	lib/util/hashutils.c \
	lib/util/hashutils.h \
	lib/util/logging.h \
	lib/util/logutils.c \
	lib/util/logutils.h \
	lib/util/macros.h \
	lib/util/queue.c \
	lib/util/queue.h \
	lib/util/semaphore_compat.c \
	lib/util/semaphore_compat.h \
	lib/util/stringutils.c \
	lib/util/stringutils.h

lib_util_libutil_a_CFLAGS = \
	$(CFLAGS_STRICT)


check_LIBRARIES += lib/util/libutildebug.a

lib_util_libutildebug_a_SOURCES = \
	$(lib_util_libutil_a_SOURCES)

lib_util_libutildebug_a_CFLAGS = \
	$(lib_util_libutil_a_CFLAGS)

lib_util_libutildebug_a_CPPFLAGS = \
	-DDEBUG


check_PROGRAMS += lib/util/tests/bag-test

lib_util_tests_bag_test_LDADD = \
	lib/util/libutildebug.a

lib_util_tests_bag_test_CFLAGS = \
	$(lib_util_libutildebug_a_CFLAGS)

TESTS += lib/util/tests/bag-test


check_PROGRAMS += lib/util/tests/queue-test

lib_util_tests_queue_test_LDADD = \
	lib/util/libutildebug.a

lib_util_tests_queue_test_CFLAGS = \
	$(lib_util_libutildebug_a_CFLAGS)

TESTS += lib/util/tests/queue-test


check_PROGRAMS += lib/util/tests/stringutils-test

lib_util_tests_stringutils_test_LDADD = \
	lib/util/libutildebug.a

lib_util_tests_stringutils_test_CFLAGS = \
	$(lib_util_libutildebug_a_CFLAGS)

TESTS += lib/util/tests/stringutils-test
