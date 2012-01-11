#


AM_CFLAGS= -g -Wall -Wshadow -Wmissing-prototypes -Wmissing-declarations \
	-DHAVE_LONG_LONG

AM_LDFLAGS = $(LIBS) -Wl,--allow-multiple-definition

AM_CPPFLAGS = $(DEPS_CFLAGS) -I../roa-lib -I../roa-utils -I../cg/asn \
	-I../cg/casn -I../utils -I. 

LDADD = librpki.a ../roa-lib/libroa.a ../cg/asn/libasn.a ../cg/casn/libcasn.a \
	../utils/libutils.a  ../utils/mysql-c-api/libmysqlcapi.a

lib_rpki_headers = scm.h scmmain.h diru.h err.h scmf.h sqhl.h myssl.h rpwork.h \
	querySupport.h conversion.h ../utils/logutils.h

lib_rpki_files = $(lib_rpki_headers) \
		initscm.c myssl.c sqhl.c sqcon.c diru.c err.c \
		querySupport.c rpwork.c conversion.c rpcommon.c

noinst_LIBRARIES = librpki.a
bin_PROGRAMS = rcli query chaser garbage makeROA proofreader testrpwork

librpki_a_SOURCES = $(lib_rpki_files)

rcli_SOURCES = rcli.c $(lib_rpki_headers)
query_SOURCES = query.c $(lib_rpki_headers)
chaser_SOURCES = chaser.c $(lib_rpki_headers)
garbage_SOURCES = garbage.c $(lib_rpki_headers)
makeROA_SOURCES = makeROA.c $(lib_rpki_headers)
proofreader_SOURCES = proofreader.c $(lib_rpki_headers)
testrpwork_SOURCES = testrpwork.c $(lib_rpki_headers)

EXTRA_DIST = *.pem *.cer *.crl sampleQuerySpecs
