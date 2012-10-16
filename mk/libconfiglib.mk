noinst_LIBRARIES += lib/configlib/libconfiglib.a

LDADD_LIBCONFIGLIB = \
	lib/configlib/libconfiglib.a \
	$(LDADD_LIBUTIL)

lib_configlib_libconfiglib_a_SOURCES = \
	lib/configlib/configlib.c \
	lib/configlib/configlib.h \
	lib/configlib/config_load.c \
	lib/configlib/config_load.h \
	lib/configlib/types/bool.c \
	lib/configlib/types/bool.h \
	lib/configlib/types/enum.c \
	lib/configlib/types/enum.h \
	lib/configlib/types/path.c \
	lib/configlib/types/path.h \
	lib/configlib/types/sscanf.c \
	lib/configlib/types/sscanf.h \
	lib/configlib/types/string.c \
	lib/configlib/types/string.h

lib_configlib_libconfiglib_a_CFLAGS = \
	$(CFLAGS_STRICT)


check_PROGRAMS += lib/configlib/tests/good

lib_configlib_tests_good_CFLAGS = \
	$(CFLAGS_STRICT)

lib_configlib_tests_good_LDADD = \
	$(LDADD_LIBCONFIGLIB)

EXTRA_DIST += \
	lib/configlib/tests/*.conf

TESTS += lib/configlib/tests/good
