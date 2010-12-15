AUTOMAKE_OPTIONS = 1.6 foreign

SUBDIRS = cg roa-lib utils proto roa-utils rsync_aur testcases server testbed

ACLOCAL_AMFLAGS = -I build-aux

test: all
	cd testcases && ./makeall
	cd subsystemTests && ./runSubsystemTest.sh 1 9
	cd subsystemTests && ./runSubsystemTest.sh 2 8
	cd subsystemTests && ./runSubsystemTest.sh 3 9
	@echo '**** All RPKI Subsystem tests ran successfully. ****'

tags:
	find ${PWD} -name \*.[ch] | xargs etags --declarations

install:
	@echo '**** Please refer to the documentation file name INSTRUCTIONS. ****'
