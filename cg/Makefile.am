AUTOMAKE_OPTIONS = 1.6 foreign
SUBDIRS = casn asn_gen asn tools

include asn/asn-files.mk

pkgdata_DATA = oidtable

oidtable: $(patsubst %,asn/%,$(GENERATED_H_FILES))
	./tools/make_oidtable $@ $^

CLEANFILES = oidtable
