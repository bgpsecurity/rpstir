bin_PROGRAMS += bin/rpki-local-ta/dumpIPAddr

bin_rpki_local_ta_dumpIPAddr_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


bin_PROGRAMS += bin/rpki-local-ta/proofreader

bin_rpki_local_ta_proofreader_LDADD = \
	$(LDADD_LIBRPKI)


bin_PROGRAMS += bin/rpki-local-ta/test_cert

bin_rpki_local_ta_test_cert_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


bin_PROGRAMS += bin/rpki-local-ta/testrpwork

bin_rpki_local_ta_testrpwork_LDADD = \
	$(LDADD_LIBRPKI)


check_PROGRAMS += tests/subsystem/rpki-local-ta/checkLTAtest

tests_subsystem_rpki_local_ta_checkLTAtest_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


check_PROGRAMS += tests/subsystem/rpki-local-ta/makeLTAtest

tests_subsystem_rpki_local_ta_makeLTAtest_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


EXTRA_DIST += \
	tests/subsystem/rpki-local-ta/test4.log \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C.cer \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C.p15 \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C1.p15 \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C1.raw \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C11.p15 \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C11.raw \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C111.raw \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C112.raw \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C113.raw \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C2.p15 \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C2.raw \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C21.p15 \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C21.raw \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C211.raw \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C3.p15 \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C3.raw \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C31.p15 \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C31.raw \
	tests/subsystem/rpki-local-ta/testcases4_LTA/C311.raw \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C.case1.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C.case2.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C.case3.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C.case4.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C1.case1.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C1.case2.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C1.case3.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C1.case4.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C11.case1.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C11.case2.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C11.case3.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C11.case4.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C111.case1.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C111.case2.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C111.case3.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C111.case4.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C2.case1.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C2.case2.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C2.case3.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C2.case4.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C21.case1.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C21.case2.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C21.case3.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C21.case4.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C211.case1.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C211.case2.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C211.case3.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/C211.case4.tst \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/LTA.cer \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/LTA.p15 \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/case1 \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/case2 \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/case3 \
	tests/subsystem/rpki-local-ta/testcases4_LTA/LTA/case4 \
	tests/subsystem/rpki-local-ta/testcases4_LTA/MYTA.cer \
	tests/subsystem/rpki-local-ta/testcases4_LTA/MYTA.p15 \
	tests/subsystem/rpki-local-ta/ttest4.1.par \
	tests/subsystem/rpki-local-ta/ttest4.2.par


check_SCRIPTS += tests/subsystem/rpki-local-ta/initDB4
MK_SUBST_FILES_EXEC += tests/subsystem/rpki-local-ta/initDB4
tests/subsystem/rpki-local-ta/initDB4: $(srcdir)/tests/subsystem/rpki-local-ta/initDB4.in


check_SCRIPTS += tests/subsystem/rpki-local-ta/runSubsystemTest4.sh
MK_SUBST_FILES_EXEC += tests/subsystem/rpki-local-ta/runSubsystemTest4.sh
tests/subsystem/rpki-local-ta/runSubsystemTest4.sh: $(srcdir)/tests/subsystem/rpki-local-ta/runSubsystemTest4.sh.in


check_SCRIPTS += tests/subsystem/rpki-local-ta/step4
MK_SUBST_FILES_EXEC += tests/subsystem/rpki-local-ta/step4
tests/subsystem/rpki-local-ta/step4: $(srcdir)/tests/subsystem/rpki-local-ta/step4.in


TESTS += tests/subsystem/rpki-local-ta/runSubsystemTest4.sh
