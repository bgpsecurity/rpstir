pkglibexec_PROGRAMS += bin/asn1/dump

bin_asn1_dump_SOURCES = \
	bin/asn1/asn_dump.c \
	bin/asn1/dump.c \
	bin/asn1/util.c

bin_asn1_dump_LDADD = \
	$(LDADD_LIBCASN)

EXTRA_DIST += doc/dump.1


pkglibexec_PROGRAMS += bin/asn1/dump_smart

bin_asn1_dump_smart_LDADD = \
	$(LDADD_LIBRPKIASN1)

EXTRA_DIST += doc/dump_smart.1


noinst_PROGRAMS += bin/asn1/make_oidtable

EXTRA_DIST += doc/make_oidtable.1


pkglibexec_PROGRAMS += bin/asn1/rr

bin_asn1_rr_LDADD = \
	$(LDADD_LIBCASN)

EXTRA_DIST += doc/rr.1
