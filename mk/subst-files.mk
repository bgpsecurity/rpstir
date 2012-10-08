do_subst = $(SED) \
	-e 's,[@]abs_top_builddir[@],$(abs_top_builddir),g' \
	-e 's,[@]abs_top_srcdir[@],$(abs_top_srcdir),g' \
	-e 's,[@]pkglibexecdir[@],$(pkglibexecdir),g' \
	-e 's,[@]CONFIG_ENV_VAR[@],$(CONFIG_ENV_VAR),g' \
	-e 's,[@]MKTEMP[@],$(MKTEMP),g'


# TODO: figure out where to distribute envir.setup
BUILT_SOURCES += etc/envir.setup
noinst_DATA += etc/envir.setup
CLEANFILES += etc/envir.setup
EXTRA_DIST += etc/envir.setup.in
etc/envir.setup: $(top_srcdir)/etc/envir.setup.in Makefile
	$(do_subst) < $(top_srcdir)/etc/envir.setup.in > "$@" || \
		rm -f "$@"

BUILT_SOURCES += tests/test.include
noinst_DATA += tests/test.include
CLEANFILES += tests/test.include
EXTRA_DIST += tests/test.include.in
tests/test.include: $(top_srcdir)/tests/test.include.in Makefile
	$(do_subst) < $(top_srcdir)/tests/test.include.in > "$@" || \
		rm -f "$@"
