pkglibexec_PROGRAMS += bin/config/config_get

bin_config_config_get_LDADD = \
	$(LDADD_LIBCONFIG)

bin_config_config_get_CFLAGS = \
	$(CFLAGS_STRICT)
