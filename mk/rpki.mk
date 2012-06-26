bin_PROGRAMS += bin/rpki/chaser

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
	tests/conformance/raw/root/*.cer \
	tests/conformance/raw/root/*.crl \
	tests/conformance/raw/root/*.mft \
	tests/conformance/raw/root/*.roa \

dist_doc_DATA += doc/conformance-cases
