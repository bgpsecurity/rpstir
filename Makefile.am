AUTOMAKE_OPTIONS = 1.6 foreign -Wall


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
noinst_LIBRARIES =
noinst_PROGRAMS =
pkgdata_DATA =
pkglibexec_PROGRAMS =

examplesdir = $(docdir)/examples

dist_check_SCRIPTS += tests/run_with_tool.sh
TESTS_ENVIRONMENT = $(top_srcdir)/tests/run_with_tool.sh

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
include mk/testbed.mk

ACLOCAL_AMFLAGS = -I build-aux -I m4

clean-local:
	-rm -rf $(CLEANDIRS)

install:
	@echo '**** Please refer to the documentation file name INSTRUCTIONS. ****'
