AUTOMAKE_OPTIONS = 1.6 foreign

SUBDIRS = \
	utils \
	cg \
	roa-lib \
	proto \
	roa-utils \
	rsync_aur \
	testcases \
	rtr \
	testbed \
	subsystemTests \
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

BUILT_SOURCES =
bin_PROGRAMS =
check_PROGRAMS =
dist_check_SCRIPTS =
noinst_LIBRARIES =
noinst_PROGRAMS =
pkgdata_DATA =

include mk/asn1.mk
include mk/libcasn.mk
include mk/librpkiasn1.mk
include mk/oidtable.mk
include mk/rpki-local-ta.mk
include mk/rpki-object.mk

ACLOCAL_AMFLAGS = -I build-aux -I m4

tags:
	find ${PWD} -name \*.[ch] | xargs etags --declarations

install:
	@echo '**** Please refer to the documentation file name INSTRUCTIONS. ****'
