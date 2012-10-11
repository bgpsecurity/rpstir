pkglibexec_PROGRAMS += bin/rpki/chaser

bin_rpki_chaser_CFLAGS = \
	$(CFLAGS_STRICT)

bin_rpki_chaser_LDADD = \
	$(LDADD_LIBDB) \
	$(LDADD_LIBUTIL)

bin_SCRIPTS += bin/rpki/chaser.sh
MK_SUBST_FILES_EXEC += bin/rpki/chaser.sh
bin/rpki/chaser.sh: $(srcdir)/bin/rpki/chaser.sh.in

check_SCRIPTS += tests/subsystem/chaser/test.sh
MK_SUBST_FILES_EXEC += tests/subsystem/chaser/test.sh
tests/subsystem/chaser/test.sh: $(srcdir)/tests/subsystem/chaser/test.sh.in

TESTS += tests/subsystem/chaser/test.sh

dist_check_DATA += \
	tests/subsystem/chaser/input.bad_chars.conf \
	tests/subsystem/chaser/input.collapse_dots.conf \
	tests/subsystem/chaser/input.collapse_slash_dot.conf \
	tests/subsystem/chaser/input.collapse_slashes.conf \
	tests/subsystem/chaser/input.max_length.conf \
	tests/subsystem/chaser/input.subsume.conf \
	tests/subsystem/chaser/response.bad_chars.log.correct \
	tests/subsystem/chaser/response.collapse_dots.log.correct \
	tests/subsystem/chaser/response.collapse_slash_dot.log.correct \
	tests/subsystem/chaser/response.collapse_slashes.log.correct \
	tests/subsystem/chaser/response.max_length.log.correct \
	tests/subsystem/chaser/response.subsume.log.correct

CLEANFILES += \
	tests/subsystem/chaser/*.diff \
	tests/subsystem/chaser/*.log


bin_PROGRAMS += bin/rpki/garbage

bin_rpki_garbage_LDADD = \
	$(LDADD_LIBRPKI)


dist_bin_SCRIPTS += bin/rpki/garbage.sh


dist_bin_SCRIPTS += bin/rpki/initDB.sh


dist_bin_SCRIPTS += bin/rpki/loader.sh


bin_PROGRAMS += bin/rpki/query

bin_rpki_query_LDADD = \
	$(LDADD_LIBRPKI)


dist_bin_SCRIPTS += bin/rpki/query.sh


bin_PROGRAMS += bin/rpki/rcli

bin_rpki_rcli_LDADD = \
	$(LDADD_LIBRPKI)


bin_SCRIPTS += bin/rpki/results.py
MK_SUBST_FILES_EXEC += bin/rpki/results.py
bin/rpki/results.py: $(srcdir)/bin/rpki/results.py.in


bin_SCRIPTS += bin/rpki/run_from_TALs.sh
MK_SUBST_FILES_EXEC += bin/rpki/run_from_TALs.sh
bin/rpki/run_from_TALs.sh: $(srcdir)/bin/rpki/run_from_TALs.sh.in


bin_SCRIPTS += bin/rpki/updateTA.py
MK_SUBST_FILES_EXEC += bin/rpki/updateTA.py
bin/rpki/updateTA.py: $(srcdir)/bin/rpki/updateTA.py.in


sampletadir = $(examplesdir)/sample-ta

conformancetadir = $(sampletadir)/bbn_conformance

dist_conformanceta_DATA = \
	etc/sample-ta/bbn_conformance/badRootNameDiff.tal \
	etc/sample-ta/bbn_conformance/badRootBadCRLDP.tal \
	etc/sample-ta/bbn_conformance/badRootBadAKI.tal \
	etc/sample-ta/bbn_conformance/root.tal


EXTRA_DIST += tests/conformance/rfc3779

dist_check_DATA += \
	tests/conformance/raw/*.p15 \
	tests/conformance/raw/*.raw \
	tests/conformance/raw/keys/*.p15 \
	tests/conformance/raw/patches/*.patch \
	tests/conformance/raw/templates/*.p15 \
	tests/conformance/raw/templates/*.raw \
	tests/conformance/scripts/conformance.conf

check_SCRIPTS += tests/conformance/scripts/gen_all.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_all.sh
tests/conformance/scripts/gen_all.sh: $(srcdir)/tests/conformance/scripts/gen_all.sh.in

check_SCRIPTS += tests/conformance/scripts/gen_all_CMSs.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_all_CMSs.sh
tests/conformance/scripts/gen_all_CMSs.sh: $(srcdir)/tests/conformance/scripts/gen_all_CMSs.sh.in

check_SCRIPTS += tests/conformance/scripts/gen_all_CRLs.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_all_CRLs.sh
tests/conformance/scripts/gen_all_CRLs.sh: $(srcdir)/tests/conformance/scripts/gen_all_CRLs.sh.in

check_SCRIPTS += tests/conformance/scripts/gen_all_MFTs.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_all_MFTs.sh
tests/conformance/scripts/gen_all_MFTs.sh: $(srcdir)/tests/conformance/scripts/gen_all_MFTs.sh.in

check_SCRIPTS += tests/conformance/scripts/gen_all_ROAs.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_all_ROAs.sh
tests/conformance/scripts/gen_all_ROAs.sh: $(srcdir)/tests/conformance/scripts/gen_all_ROAs.sh.in

check_SCRIPTS += tests/conformance/scripts/gen_all_certs.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_all_certs.sh
tests/conformance/scripts/gen_all_certs.sh: $(srcdir)/tests/conformance/scripts/gen_all_certs.sh.in

check_SCRIPTS += tests/conformance/scripts/gen_child_ca.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_child_ca.sh
tests/conformance/scripts/gen_child_ca.sh: $(srcdir)/tests/conformance/scripts/gen_child_ca.sh.in

check_SCRIPTS += tests/conformance/scripts/gen_mft.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/gen_mft.sh
tests/conformance/scripts/gen_mft.sh: $(srcdir)/tests/conformance/scripts/gen_mft.sh.in

check_SCRIPTS += tests/conformance/scripts/make_test_CMS.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/make_test_CMS.sh
tests/conformance/scripts/make_test_CMS.sh: $(srcdir)/tests/conformance/scripts/make_test_CMS.sh.in

check_SCRIPTS += tests/conformance/scripts/make_test_CRL.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/make_test_CRL.sh
tests/conformance/scripts/make_test_CRL.sh: $(srcdir)/tests/conformance/scripts/make_test_CRL.sh.in

check_SCRIPTS += tests/conformance/scripts/make_test_MFT.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/make_test_MFT.sh
tests/conformance/scripts/make_test_MFT.sh: $(srcdir)/tests/conformance/scripts/make_test_MFT.sh.in

check_SCRIPTS += tests/conformance/scripts/make_test_cert.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/make_test_cert.sh
tests/conformance/scripts/make_test_cert.sh: $(srcdir)/tests/conformance/scripts/make_test_cert.sh.in


check_SCRIPTS += tests/conformance/scripts/run_tests.sh
MK_SUBST_FILES_EXEC += tests/conformance/scripts/run_tests.sh
tests/conformance/scripts/run_tests.sh: $(srcdir)/tests/conformance/scripts/run_tests.sh.in

TESTS += \
	tests/conformance/scripts/run_tests.sh

CLEANDIRS += \
	tests/conformance/output \
	tests/conformance/raw/root

CLEANFILES += \
	tests/conformance/raw/*.cer

dist_doc_DATA += doc/conformance-cases


check_SCRIPTS += tests/subsystem/initDB
MK_SUBST_FILES_EXEC += tests/subsystem/initDB
tests/subsystem/initDB: $(srcdir)/tests/subsystem/initDB.in


check_SCRIPTS += tests/subsystem/runSubsystemTest.sh
MK_SUBST_FILES_EXEC += tests/subsystem/runSubsystemTest.sh
tests/subsystem/runSubsystemTest.sh: $(srcdir)/tests/subsystem/runSubsystemTest.sh.in


check_SCRIPTS += \
	tests/subsystem/step1.1 \
	tests/subsystem/step1.2 \
	tests/subsystem/step1.3 \
	tests/subsystem/step1.4 \
	tests/subsystem/step1.5 \
	tests/subsystem/step1.6 \
	tests/subsystem/step1.7 \
	tests/subsystem/step1.8 \
	tests/subsystem/step1.9 \
	tests/subsystem/step2.1 \
	tests/subsystem/step2.2 \
	tests/subsystem/step2.3 \
	tests/subsystem/step2.4 \
	tests/subsystem/step2.5 \
	tests/subsystem/step2.6 \
	tests/subsystem/step2.7 \
	tests/subsystem/step2.8 \
	tests/subsystem/step3.1 \
	tests/subsystem/step3.2 \
	tests/subsystem/step3.3 \
	tests/subsystem/step3.4 \
	tests/subsystem/step3.5 \
	tests/subsystem/step3.6 \
	tests/subsystem/step3.7 \
	tests/subsystem/step3.8 \
	tests/subsystem/step3.9

MK_SUBST_FILES_EXEC += \
	tests/subsystem/step1.1 \
	tests/subsystem/step1.2 \
	tests/subsystem/step1.3 \
	tests/subsystem/step1.4 \
	tests/subsystem/step1.5 \
	tests/subsystem/step1.6 \
	tests/subsystem/step1.7 \
	tests/subsystem/step1.8 \
	tests/subsystem/step1.9 \
	tests/subsystem/step2.1 \
	tests/subsystem/step2.2 \
	tests/subsystem/step2.3 \
	tests/subsystem/step2.4 \
	tests/subsystem/step2.5 \
	tests/subsystem/step2.6 \
	tests/subsystem/step2.7 \
	tests/subsystem/step2.8 \
	tests/subsystem/step3.1 \
	tests/subsystem/step3.2 \
	tests/subsystem/step3.3 \
	tests/subsystem/step3.4 \
	tests/subsystem/step3.5 \
	tests/subsystem/step3.6 \
	tests/subsystem/step3.7 \
	tests/subsystem/step3.8 \
	tests/subsystem/step3.9

tests/subsystem/step1.1: $(srcdir)/tests/subsystem/step1.1.in
tests/subsystem/step1.2: $(srcdir)/tests/subsystem/step1.2.in
tests/subsystem/step1.3: $(srcdir)/tests/subsystem/step1.3.in
tests/subsystem/step1.4: $(srcdir)/tests/subsystem/step1.4.in
tests/subsystem/step1.5: $(srcdir)/tests/subsystem/step1.5.in
tests/subsystem/step1.6: $(srcdir)/tests/subsystem/step1.6.in
tests/subsystem/step1.7: $(srcdir)/tests/subsystem/step1.7.in
tests/subsystem/step1.8: $(srcdir)/tests/subsystem/step1.8.in
tests/subsystem/step1.9: $(srcdir)/tests/subsystem/step1.9.in
tests/subsystem/step2.1: $(srcdir)/tests/subsystem/step2.1.in
tests/subsystem/step2.2: $(srcdir)/tests/subsystem/step2.2.in
tests/subsystem/step2.3: $(srcdir)/tests/subsystem/step2.3.in
tests/subsystem/step2.4: $(srcdir)/tests/subsystem/step2.4.in
tests/subsystem/step2.5: $(srcdir)/tests/subsystem/step2.5.in
tests/subsystem/step2.6: $(srcdir)/tests/subsystem/step2.6.in
tests/subsystem/step2.7: $(srcdir)/tests/subsystem/step2.7.in
tests/subsystem/step2.8: $(srcdir)/tests/subsystem/step2.8.in
tests/subsystem/step3.1: $(srcdir)/tests/subsystem/step3.1.in
tests/subsystem/step3.2: $(srcdir)/tests/subsystem/step3.2.in
tests/subsystem/step3.3: $(srcdir)/tests/subsystem/step3.3.in
tests/subsystem/step3.4: $(srcdir)/tests/subsystem/step3.4.in
tests/subsystem/step3.5: $(srcdir)/tests/subsystem/step3.5.in
tests/subsystem/step3.6: $(srcdir)/tests/subsystem/step3.6.in
tests/subsystem/step3.7: $(srcdir)/tests/subsystem/step3.7.in
tests/subsystem/step3.8: $(srcdir)/tests/subsystem/step3.8.in
tests/subsystem/step3.9: $(srcdir)/tests/subsystem/step3.9.in


check_PROGRAMS += tests/subsystem/testcases/cert_validate

tests_subsystem_testcases_cert_validate_LDADD = \
	$(LDADD_LIBRPKI)


check_PROGRAMS += tests/subsystem/testcases/gen_test_key

tests_subsystem_testcases_gen_test_key_LDADD = \
	$(LDADD_LIBUTIL)


check_PROGRAMS += tests/subsystem/testcases/make_test_cert

tests_subsystem_testcases_make_test_cert_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


check_PROGRAMS += tests/subsystem/testcases/make_test_crl

tests_subsystem_testcases_make_test_crl_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


check_PROGRAMS += tests/subsystem/testcases/make_test_manifest

tests_subsystem_testcases_make_test_manifest_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


check_PROGRAMS += tests/subsystem/testcases/make_test_roa

tests_subsystem_testcases_make_test_roa_LDADD = \
	$(LDADD_LIBRPKI)


check_SCRIPTS += tests/subsystem/testcases/tools/create_cert.py
MK_SUBST_FILES_EXEC += tests/subsystem/testcases/tools/create_cert.py
tests/subsystem/testcases/tools/create_cert.py: $(srcdir)/tests/subsystem/testcases/tools/create_cert.py.in

check_SCRIPTS += tests/subsystem/testcases/tools/run_tc.py
MK_SUBST_FILES_EXEC += tests/subsystem/testcases/tools/run_tc.py
tests/subsystem/testcases/tools/run_tc.py: $(srcdir)/tests/subsystem/testcases/tools/run_tc.py.in


dist_check_DATA += \
	tests/subsystem/testcases/*.p15 \
	tests/subsystem/testcases/C.*.orig \
	tests/subsystem/testcases/certpattern \
	tests/subsystem/testcases/false* \
	tests/subsystem/testcases/makeC* \
	tests/subsystem/testcases/makeL* \
	tests/subsystem/testcases/makeM* \
	tests/subsystem/testcases/queryIgnoreAll \
	tests/subsystem/testcases/t?-?_* \
	tests/subsystem/testcases/test1.log \
	tests/subsystem/testcases/tools/test.conf


dist_check_SCRIPTS += \
	tests/subsystem/testcases/makeall \
	tests/subsystem/testcases/makecerts \
	tests/subsystem/testcases/makecrls \
	tests/subsystem/testcases/makekeys \
	tests/subsystem/testcases/makemanifests \
	tests/subsystem/testcases/makeroas \
	tests/subsystem/testcases/print-cert-addrs.sh \
	tests/subsystem/testcases/testall.sh


CLEANDIRS += \
	tests/subsystem/testcases/C1 \
	tests/subsystem/testcases/C2 \
	tests/subsystem/testcases/EEcertificates

CLEANFILES += \
	tests/subsystem/testcases/*.crl \
	tests/subsystem/testcases/*.man \
	tests/subsystem/testcases/*.roa \
	tests/subsystem/testcases/C*.cer \
	tests/subsystem/testcases/C.raw



TESTS += tests/subsystem/testcases/makeall


dist_check_DATA += \
	tests/subsystem/specs.*.*.conf \
	tests/subsystem/test*.log


dist_check_SCRIPTS += \
	tests/subsystem/doLoader \
	tests/subsystem/make* \
	tests/subsystem/runSubsystemTest1.sh \
	tests/subsystem/runSubsystemTest2.sh \
	tests/subsystem/runSubsystemTest3.sh


CLEANFILES += \
	tests/subsystem/garbage.log \
	tests/subsystem/query.log \
	tests/subsystem/rcli.log \
	tests/subsystem/rsync_aur.log
# TODO: are there more CLEANFILES? C*.cer?


TESTS += \
	$(srcdir)/tests/subsystem/runSubsystemTest1.sh \
	$(srcdir)/tests/subsystem/runSubsystemTest2.sh \
	$(srcdir)/tests/subsystem/runSubsystemTest3.sh
