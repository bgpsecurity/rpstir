noinst_LIBRARIES += lib/rpki/librpki.a

LDADD_LIBRPKI = \
	lib/rpki/librpki.a \
	$(LDADD_LIBRPKIOBJECT)

lib_rpki_librpki_a_SOURCES = \
	lib/rpki/cms/roa_create.c \
	lib/rpki/cms/roa_general.c \
	lib/rpki/cms/roa_serialize.c \
	lib/rpki/cms/roa_utils.h \
	lib/rpki/cms/roa_validate.c \
	lib/rpki/conversion.c \
	lib/rpki/conversion.h \
	lib/rpki/db_constants.h \
	lib/rpki/diru.c \
	lib/rpki/diru.h \
	lib/rpki/err.c \
	lib/rpki/err.h \
	lib/rpki/globals.h \
	lib/rpki/initscm.c \
	lib/rpki/myssl.c \
	lib/rpki/myssl.h \
	lib/rpki/querySupport.c \
	lib/rpki/querySupport.h \
	lib/rpki/rpcommon.c \
	lib/rpki/rpwork.c \
	lib/rpki/rpwork.h \
	lib/rpki/scmf.h \
	lib/rpki/scm.h \
	lib/rpki/scmmain.h \
	lib/rpki/sqcon.c \
	lib/rpki/sqhl.c \
	lib/rpki/sqhl.h


dist_check_DATA += \
	lib/rpki/tests/roa_test/Cert.req \
	lib/rpki/tests/roa_test/keyfile.p15 \
	lib/rpki/tests/roa_test/mytest.cert.req \
	lib/rpki/tests/roa_test/roa.cnf


check_PROGRAMS += lib/rpki/tests/roa_test/roa_test

lib_rpki_tests_roa_test_roa_test_LDADD = \
	$(LDADD_LIBRPKI)


check_PROGRAMS += lib/rpki/tests/test_check_sig

lib_rpki_tests_test_check_sig_LDADD = \
	$(LDADD_LIBRPKI)


check_PROGRAMS += lib/rpki/tests/test_val2

lib_rpki_tests_test_val2_LDADD = \
	$(LDADD_LIBRPKI)
