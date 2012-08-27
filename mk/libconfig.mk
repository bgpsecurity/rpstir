noinst_LIBRARIES += lib/config/libconfig.a

LDADD_LIBCONFIG = \
	lib/config/libconfig.a \
	$(LDADD_LIBCONFIGLIB)

lib_config_libconfig_a_SOURCES = \
	lib/config/config.c \
	lib/config/config.h

lib_config_libconfig_a_CFLAGS = \
	$(CFLAGS_STRICT)
