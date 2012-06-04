AM_CFLAGS = -g -Wall -Wextra -Werror
AM_CPPFLAGS = $(DEPS_CFLAGS) -I../utils

noinst_LIBRARIES = libconfig.a

libconfig_a_SOURCES = \
	config.c config.h \
	config_parse.c config_parse.h \
	config_type.h \
	types/sscanf.c types/sscanf.h \
	types/string.c types/string.h
