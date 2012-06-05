AM_CFLAGS = -g -Wall -Wextra -Werror
AM_CPPFLAGS = $(DEPS_CFLAGS) -I../utils

EXTRA_DIST = \
	lib/tests/*.conf

noinst_LIBRARIES = \
	lib/libconfig.a \
	lib@PACKAGE_NAME@conf.a

lib_libconfig_a_SOURCES = \
	lib/configlib.c lib/configlib.h \
	lib/config_load.c lib/config_load.h \
	lib/types/sscanf.c lib/types/sscanf.h \
	lib/types/string.c lib/types/string.h

lib@PACKAGE_NAME@conf_a_SOURCES = \
	$(lib_libconfig_a_SOURCES) \
	config.c config.h

check_PROGRAMS = lib/tests/good

lib_tests_good_SOURCES = lib/tests/good.c
lib_tests_good_LDADD = lib/libconfig.a

TESTS = $(check_PROGRAMS)
