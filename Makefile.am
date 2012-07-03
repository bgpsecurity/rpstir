AUTOMAKE_OPTIONS = 1.6 foreign


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
	-I$(top_srcdir)/lib


BUILT_SOURCES =
CLEANFILES =
TESTS =
bin_PROGRAMS =
bin_SCRIPTS =
check_LIBRARIES =
check_PROGRAMS =
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

examplesdir = $(docdir)/examples

dist_check_SCRIPTS += tests/run_with_tool.sh
TESTS_ENVIRONMENT = $(top_srcdir)/tests/run_with_tool.sh

dist_doc_DATA += \
	doc/glossary.txt

dist_noinst_DATA += \
	doc/api.txt

dist_sysconf_DATA += etc/envir.setup

# library makefiles must be ordered by dependencies, lowest level library to highest
include mk/libutil.mk
include mk/libcasn.mk
include mk/librpkiasn1.mk
include mk/libdb.mk
include mk/librpkirtr.mk
include mk/librpki.mk

# other makefiles shouldn't depend on one another, so are in alphabetical order
include mk/asn1.mk
include mk/doxygen.mk
include mk/oidtable.mk
include mk/rpki-local-ta.mk
include mk/rpki-object.mk
include mk/rpki-rsync.mk
include mk/rpki-rtr.mk
include mk/rpki.mk
include mk/testbed.mk
include mk/unittest.mk

ACLOCAL_AMFLAGS = -I build-aux -I m4

tags:
	find ${PWD} -name \*.[ch] | xargs etags --declarations

install:
	@echo '**** Please refer to the documentation file name INSTRUCTIONS. ****'
