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
	trap_errors \
	version-server.pem

CLEANFILES = \
	query.log

ACLOCAL_AMFLAGS = -I build-aux -I m4

tags:
	find ${PWD} -name \*.[ch] | xargs etags --declarations

install:
	@echo '**** Please refer to the documentation file name INSTRUCTIONS. ****'
