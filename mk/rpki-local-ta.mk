pkglibexec_PROGRAMS += bin/rpki-local-ta/dumpIPAddr

bin_rpki_local_ta_dumpIPAddr_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


pkglibexec_PROGRAMS += bin/rpki-local-ta/proofreader
PACKAGE_NAME_BINS += proofreader

bin_rpki_local_ta_proofreader_LDADD = \
	$(LDADD_LIBRPKI)


pkglibexec_PROGRAMS += bin/rpki-local-ta/test_cert

bin_rpki_local_ta_test_cert_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


pkglibexec_PROGRAMS += bin/rpki-local-ta/testrpwork

bin_rpki_local_ta_testrpwork_LDADD = \
	$(LDADD_LIBRPKI)
