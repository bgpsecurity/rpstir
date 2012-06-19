bin_PROGRAMS += bin/asn1/dump

bin_asn1_dump_CPPFLAGS = \
	-Ilib/casn

bin_asn1_dump_SOURCES = \
	bin/asn1/asn_dump.c \
	bin/asn1/dump.c \
	bin/asn1/util.c

bin_asn1_dump_LDADD = \
	lib/casn/libcasn.a


bin_PROGRAMS += bin/asn1/dump_smart

bin_asn1_dump_smart_SOURCES = \
	dump_smart.c


bin_PROGRAMS += bin/asn1/make_oidtable

bin_asn1_make_oidtable_SOURCES = \
	make_oidtable.c


bin_PROGRAMS += bin/asn1/rr

bin_asn1_rr_CPPFLAGS = \
	-Ilib/casn

bin_asn1_rr_SOURCES = \
	rr.c

bin_asn1_rr_LDADD = \
	lib/casn/libcasn.a