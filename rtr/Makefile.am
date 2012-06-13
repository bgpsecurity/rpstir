AM_CFLAGS = -g -Wall -Wextra -Werror

AM_CPPFLAGS = $(DEPS_CFLAGS) -I../cg/asn -I../proto -I../cg/asn_gen \
	-I../cg/casn -I../roa-lib -I../utils -I../config

noinst_LIBRARIES = libpdu.a

bin_PROGRAMS = @PACKAGE_NAME@-rtr-update @PACKAGE_NAME@-rtrd
noinst_PROGRAMS = rtr-test-client

EXTRA_DIST = \
	cleanServerData

libpdu_a_SOURCES = pdu.c pdu.h

@PACKAGE_NAME@_rtr_update_SOURCES = rtr-update.c
@PACKAGE_NAME@_rtr_update_LDFLAGS = $(LIBS)
@PACKAGE_NAME@_rtr_update_LDADD = ../proto/librpki.a ../utils/libutils.a
@PACKAGE_NAME@_rtr_update_CFLAGS = $(AM_CFLAGS) -DHAVE_LONG_LONG

@PACKAGE_NAME@_rtrd_SOURCES = \
	cache_state.c cache_state.h \
	config.h \
	connection.c connection.h \
	connection_control.c connection_control.h \
	db.c db.h \
	main.c \
	semaphores.h \
	signals.c signals.h
@PACKAGE_NAME@_rtrd_LDADD = libpdu.a ../utils/libutils.a ../utils/mysql-c-api/libmysqlcapi.a

rtr_test_client_SOURCES = test-client.c
rtr_test_client_LDADD = libpdu.a ../utils/libutils.a
