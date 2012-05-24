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
	envir.setup \
	INSTRUCTIONS \
	LICENSE \
	README-AUTOCONF \
	run_scripts \
	trap_errors

CLEANFILES = \
	query.log

ACLOCAL_AMFLAGS = -I build-aux

if HAVE_PURIFY
.PHONY: purify
purify: all
	. "@PURIFY_SETUP@" && $(MAKE) all CC="purify -best-effort $(CC)" EXEEXT=".purify$(EXEEXT)"
@EMPTY@ifeq ($(CHECKTOOL),purify)
check: purify
@EMPTY@endif
endif

tags:
	find ${PWD} -name \*.[ch] | xargs etags --declarations

install:
	@echo '**** Please refer to the documentation file name INSTRUCTIONS. ****'
