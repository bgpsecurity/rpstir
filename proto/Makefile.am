chaser_CFLAGS = $(AM_CFLAGS) -Wextra -Werror

AM_LDFLAGS = $(LIBS) -Wl,--allow-multiple-definition

LDADD = librpki.a ../roa-lib/libroa.a ../cg/asn/libasn.a ../cg/casn/libcasn.a \
	../utils/libutils.a  ../utils/mysql-c-api/libmysqlcapi.a

bin_PROGRAMS = makeROA

makeROA_SOURCES = makeROA.c $(lib_rpki_headers)

EXTRA_DIST = *.pem *.cer *.crl
