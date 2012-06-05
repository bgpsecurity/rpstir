AM_CFLAGS = -g -Wall -Wextra -Werror
AM_CPPFLAGS = $(DEPS_CFLAGS) -I../utils

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
