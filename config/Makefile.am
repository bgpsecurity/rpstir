AM_CFLAGS = -g -Wall -Wextra -Werror
AM_CPPFLAGS = $(DEPS_CFLAGS) -I../utils

noinst_LIBRARIES = lib/libconfig.a

lib_libconfig_a_SOURCES = \
	lib/config.c lib/config.h \
	lib/config_load.c lib/config_load.h \
	lib/config_type.h \
	lib/types/sscanf.c lib/types/sscanf.h \
	lib/types/string.c lib/types/string.h
