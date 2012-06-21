AUTOMAKE_OPTIONS = 1.6 foreign

SUBDIRS = \
	. \
	proto \
	roa-utils \
	tests/subsystem/testcases \
	tests/system/testbed \
	tests/subsystem \
	doc

EXTRA_DIST = \
	autogen.sh \
	ChangeLog \
	INSTRUCTIONS \
	LICENSE \
	README \

CLEANFILES = \
	query.log

AM_CFLAGS = \
	-Wall \
	-Wextra \
	-g

CFLAGS_STRICT = \
	$(AM_CFLAGS) \
	-Werror


BUILT_SOURCES =
TESTS =
bin_PROGRAMS =
bin_SCRIPTS =
check_PROGRAMS =
check_LIBRARIES =
dist_bin_SCRIPTS =
dist_check_SCRIPTS =
dist_doc_DATA =
noinst_LIBRARIES =
noinst_PROGRAMS =
pkgdata_DATA =
dist_sysconf_DATA =

examplesdir = $(pkgdatadir)/examples

dist_check_SCRIPTS += tests/run_with_tool.sh
TESTS_ENVIRONMENT = $(top_srcdir)/tests/run_with_tool.sh

dist_sysconf_DATA += etc/envir.setup

include mk/asn1.mk
include mk/libcasn.mk
include mk/libdb.mk
include mk/librpki.mk
include mk/librpkiasn1.mk
include mk/librpkirtr.mk
include mk/libutil.mk
include mk/oidtable.mk
include mk/rpki-local-ta.mk
include mk/rpki-object.mk
include mk/rpki-rtr.mk
include mk/rpki.mk
include mk/unittest.mk

ACLOCAL_AMFLAGS = -I build-aux -I m4

tags:
	find ${PWD} -name \*.[ch] | xargs etags --declarations

install:
	@echo '**** Please refer to the documentation file name INSTRUCTIONS. ****'
