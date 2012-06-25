bin_PROGRAMS += bin/asn1/dump

bin_asn1_dump_SOURCES = \
	bin/asn1/asn_dump.c \
	bin/asn1/dump.c \
	bin/asn1/util.c

bin_asn1_dump_LDADD = \
	$(LDADD_LIBCASN)


bin_PROGRAMS += bin/asn1/dump_smart

bin_asn1_dump_smart_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/asn1/make_oidtable


bin_PROGRAMS += bin/asn1/rr

bin_asn1_rr_LDADD = \
	$(LDADD_LIBCASN)
