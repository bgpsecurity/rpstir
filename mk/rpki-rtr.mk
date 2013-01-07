pkglibexec_PROGRAMS += bin/rpki-rtr/rpki-rtr-daemon
PACKAGE_NAME_BINS += rpki-rtr-daemon

bin_rpki_rtr_rpki_rtr_daemon_SOURCES = \
	bin/rpki-rtr/cache_state.c \
	bin/rpki-rtr/cache_state.h \
	bin/rpki-rtr/config.h \
	bin/rpki-rtr/connection.c \
	bin/rpki-rtr/connection.h \
	bin/rpki-rtr/connection_control.c \
	bin/rpki-rtr/connection_control.h \
	bin/rpki-rtr/db.c \
	bin/rpki-rtr/db.h \
	bin/rpki-rtr/main.c \
	bin/rpki-rtr/semaphores.h \
	bin/rpki-rtr/signals.c \
	bin/rpki-rtr/signals.h

bin_rpki_rtr_rpki_rtr_daemon_LDADD = \
	$(LDADD_LIBDB) \
	$(LDADD_LIBRPKIRTR) \
	$(LDADD_LIBUTIL)


pkglibexec_PROGRAMS += bin/rpki-rtr/rpki-rtr-test-client
PACKAGE_NAME_BINS += rpki-rtr-test-client

bin_rpki_rtr_rpki_rtr_test_client_SOURCES = \
	bin/rpki-rtr/test-client.c

bin_rpki_rtr_rpki_rtr_test_client_LDADD = \
	$(LDADD_LIBRPKIRTR) \
	$(LDADD_LIBUTIL)


pkglibexec_PROGRAMS += bin/rpki-rtr/rpki-rtr-update
PACKAGE_NAME_BINS += rpki-rtr-update

bin_rpki_rtr_rpki_rtr_update_SOURCES = \
	bin/rpki-rtr/rtr-update.c

bin_rpki_rtr_rpki_rtr_update_LDADD = \
	$(LDADD_LIBRPKI)


pkglibexec_SCRIPTS += bin/rpki-rtr/rpki-rtr-clear
PACKAGE_NAME_BINS += rpki-rtr-clear
MK_SUBST_FILES_EXEC += bin/rpki-rtr/rpki-rtr-clear
bin/rpki-rtr/rpki-rtr-clear: $(srcdir)/bin/rpki-rtr/rpki-rtr-clear.in


EXTRA_DIST += \
	doc/rpki-rtr-daemon-outline \
	doc/rpki-rtr-notes


check_SCRIPTS += tests/subsystem/rtr/badPDUs.py
MK_SUBST_FILES_EXEC += tests/subsystem/rtr/badPDUs.py
tests/subsystem/rtr/badPDUs.py: $(srcdir)/tests/subsystem/rtr/badPDUs.py.in

check_SCRIPTS += tests/subsystem/rtr/test.sh
MK_SUBST_FILES_EXEC += tests/subsystem/rtr/test.sh
tests/subsystem/rtr/test.sh: $(srcdir)/tests/subsystem/rtr/test.sh.in

TESTS += tests/subsystem/rtr/test.sh


check_DATA += \
	tests/subsystem/rtr/as-1.roa \
	tests/subsystem/rtr/as-2.roa \
	tests/subsystem/rtr/as-3.roa \
	tests/subsystem/rtr/as-4.roa \
	tests/subsystem/rtr/as-5.roa \
	tests/subsystem/rtr/as-6.roa \
	tests/subsystem/rtr/root.cer

EXTRA_DIST += \
	tests/subsystem/rtr/ee.options \
	tests/subsystem/rtr/response.bad_pdu_sequence.log.correct \
	tests/subsystem/rtr/response.bad_pdu_usage.log.correct \
	tests/subsystem/rtr/response.bad_pdus.log.correct \
	tests/subsystem/rtr/response.no_data.log.correct \
	tests/subsystem/rtr/response.reset_query_first.log.correct \
	tests/subsystem/rtr/response.reset_query_last.log.correct \
	tests/subsystem/rtr/response.serial_notify.log.correct \
	tests/subsystem/rtr/response.serial_queries.log.correct \
	tests/subsystem/rtr/root.options \
	tests/subsystem/rtr/test.conf

RPKI_RTR_TEST_KEYS = \
	tests/subsystem/rtr/ee-1.key \
	tests/subsystem/rtr/ee-2.key \
	tests/subsystem/rtr/ee-3.key \
	tests/subsystem/rtr/ee-4.key \
	tests/subsystem/rtr/ee-5.key \
	tests/subsystem/rtr/ee-6.key \
	tests/subsystem/rtr/root.key

CLEANFILES += $(RPKI_RTR_TEST_KEYS)

$(RPKI_RTR_TEST_KEYS):
	mkdir -p "$(@D)"
	TEST_LOG_NAME=`basename "$@"` \
		TEST_LOG_DIR=`dirname "$@"` \
		STRICT_CHECKS=0 \
		$(TESTS_ENVIRONMENT) bin/rpki-object/gen_key "$@" 2048

CLEANFILES += tests/subsystem/rtr/root.cer

tests/subsystem/rtr/root.cer: tests/subsystem/rtr/root.key $(top_srcdir)/tests/subsystem/rtr/root.options
	mkdir -p "$(@D)"
	TEST_LOG_NAME=`basename "$@"` \
		TEST_LOG_DIR=`dirname "$@"` \
		STRICT_CHECKS=0 \
		$(TESTS_ENVIRONMENT) bin/rpki-object/create_object/create_object \
		-f $(top_srcdir)/tests/subsystem/rtr/root.options \
		CERT \
		outputfilename="$@" \
		subjkeyfile="tests/subsystem/rtr/root.key"

RPKI_RTR_TEST_EE_CERTS = \
	tests/subsystem/rtr/as-1.ee.cer \
	tests/subsystem/rtr/as-2.ee.cer \
	tests/subsystem/rtr/as-3.ee.cer \
	tests/subsystem/rtr/as-4.ee.cer \
	tests/subsystem/rtr/as-5.ee.cer \
	tests/subsystem/rtr/as-6.ee.cer

CLEANFILES += $(RPKI_RTR_TEST_EE_CERTS)

tests/subsystem/rtr/as-1.ee.cer: tests/subsystem/rtr/ee-1.key
tests/subsystem/rtr/as-2.ee.cer: tests/subsystem/rtr/ee-2.key
tests/subsystem/rtr/as-3.ee.cer: tests/subsystem/rtr/ee-3.key
tests/subsystem/rtr/as-4.ee.cer: tests/subsystem/rtr/ee-4.key
tests/subsystem/rtr/as-5.ee.cer: tests/subsystem/rtr/ee-5.key
tests/subsystem/rtr/as-6.ee.cer: tests/subsystem/rtr/ee-6.key
$(RPKI_RTR_TEST_EE_CERTS): tests/subsystem/rtr/root.key tests/subsystem/rtr/root.cer $(top_srcdir)/tests/subsystem/rtr/ee.options
	mkdir -p "$(@D)"
	number=`echo "$(@F)" | sed -e "s/^as-//" -e "s/\\.ee\\.cer\$$//"`; \
	key="$(@D)/ee-$$number.key"; \
	IP4="`printf '%u.0.1.0-%u.0.%u.255,%u.1.0.0-%u.%u.255.255' $$number $$number $$number $$number $$number $$number`"; \
	IP6="`printf '%x::100-%x::%xff,%x:1::-%x:%x:ffff:ffff:ffff:ffff:ffff:ffff' $$number $$number $$number $$number $$number $$number`"; \
	TEST_LOG_NAME=`basename "$@"` \
		TEST_LOG_DIR=`dirname "$@"` \
		STRICT_CHECKS=0 \
		$(TESTS_ENVIRONMENT) bin/rpki-object/create_object/create_object \
		-f $(top_srcdir)/tests/subsystem/rtr/ee.options \
		CERT \
		outputfilename="$@" \
		parentcertfile=tests/subsystem/rtr/root.cer \
		parentkeyfile=tests/subsystem/rtr/root.key \
		subjkeyfile="$$key" \
		serial="$$number" \
		subject="as$$number" \
		ipv4="$$IP4" \
		ipv6="$$IP6" \
		as="$$number"

RPKI_RTR_TEST_ROAS = \
	tests/subsystem/rtr/as-1.roa \
	tests/subsystem/rtr/as-2.roa \
	tests/subsystem/rtr/as-3.roa \
	tests/subsystem/rtr/as-4.roa \
	tests/subsystem/rtr/as-5.roa \
	tests/subsystem/rtr/as-6.roa

CLEANFILES += $(RPKI_RTR_TEST_ROAS)

tests/subsystem/rtr/as-1.roa: tests/subsystem/rtr/as-1.ee.cer tests/subsystem/rtr/ee-1.key
tests/subsystem/rtr/as-2.roa: tests/subsystem/rtr/as-2.ee.cer tests/subsystem/rtr/ee-2.key
tests/subsystem/rtr/as-3.roa: tests/subsystem/rtr/as-3.ee.cer tests/subsystem/rtr/ee-3.key
tests/subsystem/rtr/as-4.roa: tests/subsystem/rtr/as-4.ee.cer tests/subsystem/rtr/ee-4.key
tests/subsystem/rtr/as-5.roa: tests/subsystem/rtr/as-5.ee.cer tests/subsystem/rtr/ee-5.key
tests/subsystem/rtr/as-6.roa: tests/subsystem/rtr/as-6.ee.cer tests/subsystem/rtr/ee-6.key
$(RPKI_RTR_TEST_ROAS):
	mkdir -p "$(@D)"
	number=`echo "$(@F)" | sed -e "s/^as-//" -e "s/\\.roa\$$//"`; \
	ee_cer="$(@D)/as-$$number.ee.cer"; \
	key="$(@D)/ee-$$number.key"; \
	IP4=""; IP6=""; \
	for IP_OCTET in `seq 1 "$$number"`; do \
		IP4="$$IP4,`printf '%u.0.%u.0/24%%25' $$number $$IP_OCTET`"; \
		IP6="$$IP6,`printf '%x::%x00/120' $$number $$IP_OCTET`"; \
	done; \
	for IP_OCTET in `seq 1 "$$number"`; do \
		IP4="$$IP4,`printf '%u.%u.0.0/16' $$number $$IP_OCTET`"; \
		IP6="$$IP6,`printf '%x:%x::/32%%127' $$number $$IP_OCTET`"; \
	done; \
	IP4=`echo "$$IP4" | cut -c 2-`; \
	IP6=`echo "$$IP6" | cut -c 2-`; \
	TEST_LOG_NAME=`basename "$@"` \
		TEST_LOG_DIR=`dirname "$@"` \
		STRICT_CHECKS=0 \
		$(TESTS_ENVIRONMENT) bin/rpki-object/create_object/create_object \
		ROA \
		outputfilename="$@" \
		eecertlocation="$$ee_cer" \
		eekeylocation="$$key" \
		asid="$$number" \
		roaipv4="$$IP4" \
		roaipv6="$$IP6"


CLEANFILES += \
	tests/subsystem/rtr/*.diff \
	tests/subsystem/rtr/*.log

CLEANDIRS += \
	tests/subsystem/rtr/EEcertificates
