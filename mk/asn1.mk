pkglibexec_PROGRAMS += bin/asn1/dump

bin_asn1_dump_SOURCES = \
	bin/asn1/asn_dump.c \
	bin/asn1/dump.c \
	bin/asn1/util.c

bin_asn1_dump_LDADD = \
	$(LDADD_LIBCASN)

dist_man_MANS += doc/dump.1


pkglibexec_PROGRAMS += bin/asn1/dump_smart

bin_asn1_dump_smart_LDADD = \
	$(LDADD_LIBRPKIASN1)

dist_man_MANS += doc/dump_smart.1


bin_PROGRAMS += bin/asn1/make_oidtable

dist_man_MANS += doc/make_oidtable.1


pkglibexec_PROGRAMS += bin/asn1/rr

bin_asn1_rr_LDADD = \
	$(LDADD_LIBCASN)

dist_man_MANS += doc/rr.1
