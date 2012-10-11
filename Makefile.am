AUTOMAKE_OPTIONS = \
	1.6 \
	foreign \
	subdir-objects \
	-Wall


EXTRA_DIST = \
	autogen.sh \
	ChangeLog \
	INSTRUCTIONS \
	LICENSE \
	README

AM_CFLAGS = \
	-Wall \
	-Wextra \
	-g

CFLAGS_STRICT = \
	$(AM_CFLAGS) \
	-Werror

AM_CPPFLAGS = \
	-I$(top_srcdir)/lib \
	-DABS_TOP_SRCDIR='"@abs_top_srcdir@"' \
	-DSYSCONFDIR='"$(sysconfdir)"'

AM_ETAGSFLAGS = \
	--declarations


examplesdir = $(docdir)/examples
pkgcachedir = $(localstatedir)/cache/$(PACKAGE_NAME)
pkglogdir = $(localstatedir)/log/$(PACKAGE_NAME)
templatesdir = $(pkgdatadir)/templates

## Lists of all files to be generated from .in files by make.
## The first list is for normal files, the second is for files that should be
## executable. NOTE: neither list can contain macros (variable). They MUST be
## lists of hardcoded filenames.
MK_SUBST_FILES =
MK_SUBST_FILES_EXEC =

BUILT_SOURCES =
CLEANDIRS =
CLEANFILES =
TESTS =
bin_PROGRAMS =
bin_SCRIPTS =
check_DATA =
check_LIBRARIES =
check_PROGRAMS =
check_SCRIPTS =
dist_bin_SCRIPTS =
dist_check_DATA =
dist_check_SCRIPTS =
dist_doc_DATA =
dist_man_MANS =
dist_noinst_DATA =
dist_pkgdata_DATA =
dist_sysconf_DATA =
examples_DATA =
noinst_DATA =
noinst_LIBRARIES =
noinst_PROGRAMS =
pkgdata_DATA =
pkglibexec_PROGRAMS =
pkglibexec_SCRIPTS =

dist_check_DATA += \
	etc/test.conf \
	tests/test.conf

check_SCRIPTS += tests/setup_test_environment.sh
MK_SUBST_FILES_EXEC += tests/setup_test_environment.sh
tests/setup_test_environment.sh: $(srcdir)/tests/setup_test_environment.sh.in

## Anything that uses $(TESTS_ENVIRONMENT) before "make all" finishes should
## depend on this.
TESTS_ENVIRONTMENT_DEPS = \
	tests/setup_test_environment.sh \
	tests/test.include

TESTS_ENVIRONMENT = $(top_builddir)/tests/setup_test_environment.sh

dist_doc_DATA += \
	doc/glossary.txt

dist_noinst_DATA += \
	doc/api.txt

# library makefiles must be ordered by dependencies, lowest level library to highest
include mk/libtest.mk
include mk/libutil.mk
include mk/libconfiglib.mk
include mk/libconfig.mk
include mk/libcasn.mk
include mk/librpkiasn1.mk
include mk/librpkiobject.mk
include mk/libdb.mk
include mk/librpkirtr.mk
include mk/librpki.mk

# other makefiles shouldn't depend on one another, so are in alphabetical order
include mk/asn1.mk
include mk/config.mk
include mk/doxygen.mk
include mk/oidtable.mk
include mk/rpki-local-ta.mk
include mk/rpki-object.mk
include mk/rpki-rsync.mk
include mk/rpki-rtr.mk
include mk/rpki.mk
include mk/subst-files.mk
include mk/testbed.mk

ACLOCAL_AMFLAGS = -I build-aux -I m4

clean-local:
	-rm -rf $(CLEANDIRS)


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

## Rules for generating files from .in.
## NOTE: Each file should already have its own dependency target like
##       "foo: $(srcdir)/foo.in" defined elsewhere.
do_subst = $(SED) \
	-e 's,[@]abs_top_builddir[@],$(abs_top_builddir),g' \
	-e 's,[@]abs_top_srcdir[@],$(abs_top_srcdir),g' \
	-e 's,[@]pkgcachedir[@],$(pkgcachedir),g' \
	-e 's,[@]pkglibexecdir[@],$(pkglibexecdir),g' \
	-e 's,[@]pkglogdir[@],$(pkglogdir),g' \
	-e 's,[@]CONFIG_ENV_VAR[@],$(CONFIG_ENV_VAR),g' \
	-e 's,[@]MKTEMP[@],$(MKTEMP),g' \
	-e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	-e 's,[@]PYTHON[@],$(PYTHON),g' \
	-e 's,[@]SETUP_ENVIRONMENT[@],$(SETUP_ENVIRONMENT),g' \
	-e 's,[@]SHELL_BASH[@],$(SHELL_BASH),g'

$(MK_SUBST_FILES): Makefile
	rm -f "$@"
	$(do_subst) < "$(srcdir)/$@.in" > "$@" || rm -f "$@"

$(MK_SUBST_FILES_EXEC): Makefile
	rm -f "$@"
	$(do_subst) < "$(srcdir)/$@.in" > "$@" && chmod +x "$@" || rm -f "$@"

CLEANFILES += $(MK_SUBST_FILES) $(MK_SUBST_FILES_EXEC)
EXTRA_DIST += $(MK_SUBST_FILES:=.in) $(MK_SUBST_FILES_EXEC:=.in)
