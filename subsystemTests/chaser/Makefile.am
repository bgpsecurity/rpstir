AUTOMAKE_OPTIONS = 1.6 foreign

TESTS = ./runChaserTest.sh

check_SCRIPTS = runChaserTest.sh
check_DATA = input.* *.correct

EXTRA_DIST = $(check_SCRIPTS) $(check_DATA)

CLEANFILES = *.log *.diff
