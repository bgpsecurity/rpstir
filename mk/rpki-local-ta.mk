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


dist_check_DATA += \
	tests/subsystem/rpki-local-ta/test4.log \
	tests/subsystem/rpki-local-ta/testcases4_LTA \
	tests/subsystem/rpki-local-ta/ttest*.par


check_SCRIPTS += tests/subsystem/rpki-local-ta/initDB4
MK_SUBST_FILES_EXEC += tests/subsystem/rpki-local-ta/initDB4
tests/subsystem/rpki-local-ta/initDB4: $(srcdir)/tests/subsystem/rpki-local-ta/initDB4.in


check_SCRIPTS += tests/subsystem/rpki-local-ta/runSubsystemTest4.sh
MK_SUBST_FILES_EXEC += tests/subsystem/rpki-local-ta/runSubsystemTest4.sh
tests/subsystem/rpki-local-ta/runSubsystemTest4.sh: $(srcdir)/tests/subsystem/rpki-local-ta/runSubsystemTest4.sh


check_SCRIPTS += tests/subsystem/rpki-local-ta/step4
MK_SUBST_FILES_EXEC += tests/subsystem/rpki-local-ta/step4
tests/subsystem/rpki-local-ta/step4: $(srcdir)/tests/subsystem/rpki-local-ta/step4.in


TESTS += tests/subsystem/rpki-local-ta/runSubsystemTest4.sh
