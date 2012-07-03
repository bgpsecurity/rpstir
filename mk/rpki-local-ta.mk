bin_PROGRAMS += bin/rpki-local-ta/dumpIPAddr

bin_rpki_local_ta_dumpIPAddr_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-local-ta/proofreader

bin_rpki_local_ta_proofreader_LDADD = \
	$(LDADD_LIBRPKI)


bin_PROGRAMS += bin/rpki-local-ta/test_cert

bin_rpki_local_ta_test_cert_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-local-ta/testrpwork

bin_rpki_local_ta_testrpwork_LDADD = \
	$(LDADD_LIBRPKI)


check_PROGRAMS += tests/subsystem/rpki-local-ta/checkLTAtest

tests_subsystem_rpki_local_ta_checkLTAtest_LDADD = \
	$(LDADD_LIBRPKIASN1)


check_PROGRAMS += tests/subsystem/rpki-local-ta/makeLTAtest

tests_subsystem_rpki_local_ta_makeLTAtest_LDADD = \
	$(LDADD_LIBRPKIASN1)


dist_check_DATA += \
	tests/subsystem/rpki-local-ta/testcases4_LTA \
	tests/subsystem/rpki-local-ta/ttest*.par


TESTS += tests/subsystem/rpki-local-ta/runSubsystemTest4.sh
