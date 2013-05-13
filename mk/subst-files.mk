## Handle $(MK_SUBST_FILES) and $(MK_SUBST_FILES_EXEC)


## Extra variables for substitution in .in files.

## preamble for shell scripts
SETUP_ENVIRONMENT = \
	if test -n "$$TESTS_TOP_BUILDDIR" -a -n "$$TESTS_TOP_SRCDIR"; then \
		. "$$TESTS_TOP_SRCDIR/lib/util/shell_utils"; \
		. "$$TESTS_TOP_BUILDDIR/etc/envir.setup"; \
		. "$$TESTS_TOP_BUILDDIR/tests/test.include"; \
	else \
		. "$(pkgdatadir)/shell_utils"; \
		. "$(pkgdatadir)/envir.setup"; \
	fi

## pull in lib/util/trap_errors
trap_errors = \
	if test -n "$$TESTS_TOP_BUILDDIR" -a -n "$$TESTS_TOP_SRCDIR"; then \
		. "$$TESTS_TOP_SRCDIR/lib/util/trap_errors"; \
	else \
		. "$(pkgdatadir)/trap_errors"; \
	fi


## Rules for generating files from .in.
## NOTE: Each file should already have its own dependency target like
##       "foo: $(srcdir)/foo.in" defined elsewhere.
##
## The reason for doing this "manually" is that scripts need
## hard-coded paths rather than variables like $(prefix), which is
## desirable for Makefiles.  Thus, instead of generating fooscript
## from fooscript.in at 'configure' time, we must hold off on
## generating them until 'make' time, at which point we apply the
## substitutions below.  See below for rationale:
## http://www.gnu.org/savannah-checkouts/gnu/autoconf/manual/autoconf-2.69/html_node/Installation-Directory-Variables.html
do_subst = $(SED) \
	-e 's,[@]abs_top_builddir[@],$(abs_top_builddir),g' \
	-e 's,[@]abs_top_srcdir[@],$(abs_top_srcdir),g' \
	-e 's,[@]pkgcachedir[@],$(pkgcachedir),g' \
	-e 's,[@]pkglibexecdir[@],$(pkglibexecdir),g' \
	-e 's,[@]pkglogdir[@],$(pkglogdir),g' \
	-e 's,[@]pkgsysconfdir[@],$(pkgsysconfdir),g' \
	-e 's,[@]sampletadir[@],$(sampletadir),g' \
	-e 's,[@]trap_errors[@],$(trap_errors),g' \
	-e 's,[@]CONFIG_ENV_VAR[@],$(CONFIG_ENV_VAR),g' \
	-e 's,[@]MKTEMP[@],$(MKTEMP),g' \
	-e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	-e 's,[@]PACKAGE_SYS_CONF_FILE[@],$(PACKAGE_SYS_CONF_FILE),g' \
	-e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
	-e 's,[@]PYTHON[@],$(PYTHON),g' \
	-e 's,[@]SETUP_ENVIRONMENT[@],$(SETUP_ENVIRONMENT),g' \
	-e 's,[@]SHELL_BASH[@],$(SHELL_BASH),g'

$(MK_SUBST_FILES): Makefile
	$(AM_V_GEN)rm -f "$@" && \
	mkdir -p "$(@D)" && \
	$(do_subst) < "$(srcdir)/$@.in" > "$@" || rm -f "$@"

$(MK_SUBST_FILES_EXEC): Makefile
	$(AM_V_GEN)rm -f "$@" && \
	mkdir -p "$(@D)" && \
	$(do_subst) < "$(srcdir)/$@.in" > "$@" && chmod +x "$@" || rm -f "$@"

CLEANFILES += $(MK_SUBST_FILES) $(MK_SUBST_FILES_EXEC)
EXTRA_DIST += $(MK_SUBST_FILES:=.in) $(MK_SUBST_FILES_EXEC:=.in)
