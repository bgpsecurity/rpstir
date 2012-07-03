bin_PROGRAMS += bin/rpki-rtr/@PACKAGE_NAME@-rpki-rtr-daemon

bin_rpki_rtr_@PACKAGE_NAME@_rpki_rtr_daemon_SOURCES = \
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

bin_rpki_rtr_@PACKAGE_NAME@_rpki_rtr_daemon_LDADD = \
	$(LDADD_LIBDB) \
	$(LDADD_LIBRPKIRTR) \
	$(LDADD_LIBUTIL)

bin_rpki_rtr_@PACKAGE_NAME@_rpki_rtr_daemon_CFLAGS = \
	$(CFLAGS_STRICT)


bin_PROGRAMS += bin/rpki-rtr/@PACKAGE_NAME@-rpki-rtr-test-client

bin_rpki_rtr_@PACKAGE_NAME@_rpki_rtr_test_client_SOURCES = \
	bin/rpki-rtr/test-client.c

bin_rpki_rtr_@PACKAGE_NAME@_rpki_rtr_test_client_LDADD = \
	$(LDADD_LIBRPKIRTR) \
	$(LDADD_LIBUTIL)

bin_rpki_rtr_@PACKAGE_NAME@_rpki_rtr_test_client_CFLAGS = \
	$(CFLAGS_STRICT)


bin_PROGRAMS += bin/rpki-rtr/@PACKAGE_NAME@-rpki-rtr-update

bin_rpki_rtr_@PACKAGE_NAME@_rpki_rtr_update_SOURCES = \
	bin/rpki-rtr/rtr-update.c

bin_rpki_rtr_@PACKAGE_NAME@_rpki_rtr_update_LDADD = \
	$(LDADD_LIBRPKI)

bin_rpki_rtr_@PACKAGE_NAME@_rpki_rtr_update_CFLAGS = \
	$(CFLAGS_STRICT)


EXTRA_DIST += bin/rpki-rtr/cleanServerData


dist_doc_DATA += doc/rpki-rtr-daemon-outline


dist_doc_DATA += doc/rpki-rtr-notes


check_SCRIPTS += tests/subsystem/rtr/test.sh

TESTS += tests/subsystem/rtr/test.sh


check_DATA += \
	tests/subsystem/rtr/as-1.roa \
	tests/subsystem/rtr/as-2.roa \
	tests/subsystem/rtr/as-3.roa \
	tests/subsystem/rtr/as-4.roa \
	tests/subsystem/rtr/as-5.roa \
	tests/subsystem/rtr/as-6.roa \
	tests/subsystem/rtr/root.cer

dist_check_DATA += \
	tests/subsystem/rtr/*.correct \
	tests/subsystem/rtr/*.options \
	tests/subsystem/rtr/querySpecs

tests/subsystem/rtr/%.key:
	bin/rpki-object/gen_key "$@" 2048

tests/subsystem/rtr/root.cer: tests/subsystem/rtr/root.key $(top_srcdir)/tests/subsystem/rtr/root.options
	bin/rpki-object/create_object/create_object \
		-f $(top_srcdir)/tests/subsystem/rtr/root.options \
		CERT \
		outputfilename=tests/subsystem/rtr/"$@" \
		subjkeyfile=tests/subsystem/rtr/"$<"

tests/subsystem/rtr/as-%.ee.cer: tests/subsystem/rtr/ee-%.key tests/subsystem/rtr/root.key tests/subsystem/rtr/root.cer $(top_srcdir)/tests/subsystem/rtr/ee.options
	IP4="`printf '%u.0.1.0-%u.0.%u.255,%u.1.0.0-%u.%u.255.255' '$*' '$*' '$*' '$*' '$*' '$*'`"; \
	IP6="`printf '%x::100-%x::%xff,%x:1::-%x:%x:ffff:ffff:ffff:ffff:ffff:ffff' '$*' '$*' '$*' '$*' '$*' '$*'`"; \
	bin/rpki-object/create_object/create_object \
		-f $(top_srcdir)/tests/subsystem/rtr/ee.options \
		CERT \
		outputfilename=tests/subsystem/rtr/"$@" \
		parentcertfile=tests/subsystem/rtr/root.cer \
		parentkeyfile=tests/subsystem/rtr/root.key \
		subjkeyfile=tests/subsystem/rtr/"$<" \
		serial="$*" \
		subject="as$*" \
		ipv4="$$IP4" \
		ipv6="$$IP6" \
		as="$*"

tests/subsystem/rtr/as-%.roa: tests/subsystem/rtr/as-%.ee.cer tests/subsystem/rtr/ee-%.key
	IP4=""; IP6=""; \
	for IP_OCTET in `seq 1 "$*"`; do \
		IP4="$$IP4,`printf '%u.0.%u.0/24%%25' '$*' $$IP_OCTET`"; \
		IP6="$$IP6,`printf '%x::%x00/120' '$*' $$IP_OCTET`"; \
	done; \
	for IP_OCTET in `seq 1 "$*"`; do \
		IP4="$$IP4,`printf '%u.%u.0.0/16' '$*' $$IP_OCTET`"; \
		IP6="$$IP6,`printf '%x:%x::/32%%127' '$*' $$IP_OCTET`"; \
	done; \
	IP4=`echo "$$IP4" | cut -c 2-`; \
	IP6=`echo "$$IP6" | cut -c 2-`; \
	bin/rpki-object/create_object/create_object \
		ROA \
		outputfilename=tests/subsystem/rtr/"$@" \
		eecertlocation=tests/subsystem/rtr/"$<" \
		eekeylocation=tests/subsystem/rtr/"ee-$*.key" \
		asid="$*" \
		roaipv4="$$IP4" \
		roaipv6="$$IP6"


CLEANFILES += \
	tests/subsystem/rtr/*.cer \
	tests/subsystem/rtr/*.diff \
	tests/subsystem/rtr/*.key \
	tests/subsystem/rtr/*.log \
	tests/subsystem/rtr/*.roa
