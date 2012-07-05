bin_PROGRAMS += bin/rpki/chaser

bin_rpki_chaser_CFLAGS = \
	$(CFLAGS_STRICT)

bin_rpki_chaser_LDADD = \
	$(LDADD_LIBDB) \
	$(LDADD_LIBUTIL)

dist_check_SCRIPTS += tests/subsystem/chaser/test.sh

TESTS += tests/subsystem/chaser/test.sh

dist_check_DATA += \
	tests/subsystem/chaser/input.bad_chars \
	tests/subsystem/chaser/input.collapse_dots \
	tests/subsystem/chaser/input.collapse_slash_dot \
	tests/subsystem/chaser/input.collapse_slashes \
	tests/subsystem/chaser/input.max_length \
	tests/subsystem/chaser/input.subsume \
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


dist_sysconf_DATA += etc/additional_rsync_uris.config


sampletadir = $(examplesdir)/sample-ta

conformancetadir = $(sampletadir)/bbn_conformance

dist_conformanceta_DATA = \
	etc/sample-ta/bbn_conformance/badRootNameDiff.tal \
	etc/sample-ta/bbn_conformance/badRootBadCRLDP.tal \
	etc/sample-ta/bbn_conformance/badRootBadAKI.tal \
	etc/sample-ta/bbn_conformance/root.tal


dist_sysconf_DATA += etc/sampleQuerySpecs


EXTRA_DIST += tests/conformance/rfc3779

dist_check_DATA += \
	tests/conformance/raw/*.p15 \
	tests/conformance/raw/*.raw \
	tests/conformance/raw/keys/*.p15 \
	tests/conformance/raw/patches/*.patch \
	tests/conformance/raw/templates/*.p15 \
	tests/conformance/raw/templates/*.raw \
	tests/conformance/scripts/querySpecs

dist_check_SCRIPTS += \
	tests/conformance/scripts/run_bad_cert_tests.sh \
	tests/conformance/scripts/run_tests.sh

TESTS += \
	tests/conformance/scripts/run_tests.sh

CLEANFILES += \
	tests/conformance/output \
	tests/conformance/raw/*.cer \
	tests/conformance/raw/root

dist_doc_DATA += doc/conformance-cases


check_PROGRAMS += tests/subsystem/testcases/cert_validate

tests_subsystem_testcases_cert_validate_LDADD = \
	$(LDADD_LIBRPKI)


check_PROGRAMS += tests/subsystem/testcases/gen_test_key


check_PROGRAMS += tests/subsystem/testcases/make_test_cert

tests_subsystem_testcases_make_test_cert_SOURCES = \
	tests/subsystem/testcases/adjustTime.c \
	tests/subsystem/testcases/make_test_cert.c


tests_subsystem_testcases_make_test_cert_LDADD = \
	$(LDADD_LIBRPKIASN1)


check_PROGRAMS += tests/subsystem/testcases/make_test_crl

tests_subsystem_testcases_make_test_crl_SOURCES = \
	tests/subsystem/testcases/adjustTime.c \
	tests/subsystem/testcases/make_test_crl.c

tests_subsystem_testcases_make_test_crl_LDADD = \
	$(LDADD_LIBRPKIASN1)


check_PROGRAMS += tests/subsystem/testcases/make_test_manifest

tests_subsystem_testcases_make_test_manifest_SOURCES = \
	tests/subsystem/testcases/adjustTime.c \
	tests/subsystem/testcases/make_test_manifest.c

tests_subsystem_testcases_make_test_manifest_LDADD = \
	$(LDADD_LIBRPKI)


check_PROGRAMS += tests/subsystem/testcases/make_test_roa

tests_subsystem_testcases_make_test_roa_LDADD = \
	$(LDADD_LIBRPKI)


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


CLEANFILES += \
	tests/subsystem/testcases/*.crl \
	tests/subsystem/testcases/*.man \
	tests/subsystem/testcases/*.roa \
	tests/subsystem/testcases/C*.cer \
	tests/subsystem/testcases/C.raw \
	tests/subsystem/testcases/C1 \
	tests/subsystem/testcases/C2 \
	tests/subsystem/testcases/EEcertificates



TESTS += tests/subsystem/testcases/makeall


dist_check_DATA += \
	tests/subsystem/specs.*.* \
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
	tests/subsystem/runSubsystemTest1.sh \
	tests/subsystem/runSubsystemTest2.sh \
	tests/subsystem/runSubsystemTest3.sh
