AUTOMAKE_OPTIONS = 1.6 foreign

SUBDIRS = utils cg roa-lib proto roa-utils rsync_aur testcases rtr testbed

EXTRA_DIST = \
	autogen.sh \
	doc \
	envir.setup \
	INSTRUCTIONS \
	license \
	README-AUTOCONF \
	run_scripts \
	subsystemTests \
	testing \
	trap_errors

CLEANFILES = \
	query.log

ACLOCAL_AMFLAGS = -I build-aux

check-local:
	cd testcases && ./makeall
	cd subsystemTests && ./runSubsystemTest.sh 1 9
	cd subsystemTests && ./runSubsystemTest.sh 2 8
	cd subsystemTests && ./runSubsystemTest.sh 3 9
	cd subsystemTests && ./runSubsystemTest4.sh
	cd subsystemTests/rtr && ./runRTRTest.sh
	@echo '**** All RPKI Subsystem tests ran successfully. ****'

tags:
	find ${PWD} -name \*.[ch] | xargs etags --declarations

install:
	@echo '**** Please refer to the documentation file name INSTRUCTIONS. ****'
