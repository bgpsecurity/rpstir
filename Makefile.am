AUTOMAKE_OPTIONS = 1.6 foreign

SUBDIRS = \
	. \
	roa-lib \
	proto \
	roa-utils \
	rsync_aur \
	tests/subsystem/testcases \
	rtr \
	tests/system/testbed \
	tests/subsystem \
	doc

EXTRA_DIST = \
	autogen.sh \
	ChangeLog \
	envir.setup \
	INSTRUCTIONS \
	LICENSE \
	README-AUTOCONF \
	run_scripts \
	trap_errors

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
check_PROGRAMS =
check_LIBRARIES =
dist_check_SCRIPTS =
noinst_LIBRARIES =
noinst_PROGRAMS =
pkgdata_DATA =

dist_check_SCRIPTS += tests/run_with_tool.sh
TESTS_ENVIRONMENT = $(top_srcdir)/tests/run_with_tool.sh

include mk/asn1.mk
include mk/libcasn.mk
include mk/libdb.mk
include mk/librpkiasn1.mk
include mk/libutil.mk
include mk/oidtable.mk
include mk/rpki-local-ta.mk
include mk/rpki-object.mk
include mk/unittest.mk

ACLOCAL_AMFLAGS = -I build-aux -I m4

tags:
	find ${PWD} -name \*.[ch] | xargs etags --declarations

install:
	@echo '**** Please refer to the documentation file name INSTRUCTIONS. ****'
