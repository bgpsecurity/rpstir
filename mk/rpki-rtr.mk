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
	lib/db/libdb.a \
	lib/rpki-rtr/librpkirtr.a \
	lib/util/libutil.a

bin_rpki_rtr_@PACKAGE_NAME@_rpki_rtr_daemon_CFLAGS = \
	$(CFLAGS_STRICT)


bin_PROGRAMS += bin/rpki-rtr/@PACKAGE_NAME@-rpki-rtr-test-client

bin_rpki_rtr_@PACKAGE_NAME@_rpki_rtr_test_client_SOURCES = \
	bin/rpki-rtr/test-client.c

bin_rpki_rtr_@PACKAGE_NAME@_rpki_rtr_test_client_LDADD = \
	lib/rpki-rtr/librpkirtr.a \
	lib/util/libutil.a

bin_rpki_rtr_@PACKAGE_NAME@_rpki_rtr_test_client_CFLAGS = \
	$(CFLAGS_STRICT)


bin_PROGRAMS += bin/rpki-rtr/@PACKAGE_NAME@-rpki-rtr-update

bin_rpki_rtr_@PACKAGE_NAME@_rpki_rtr_update_SOURCES = \
	bin/rpki-rtr/rtr-update.c

bin_rpki_rtr_@PACKAGE_NAME@_rpki_rtr_update_LDADD = \
	lib/rpki/librpki.a \
	lib/util/libutil.a

bin_rpki_rtr_@PACKAGE_NAME@_rpki_rtr_update_CFLAGS = \
	$(CFLAGS_STRICT)


EXTRA_DIST += bin/rpki-rtr/cleanServerData
