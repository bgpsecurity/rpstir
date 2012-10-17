pkgdata_DATA += var/oidtable
CLEANFILES += var/oidtable

var/oidtable: ./bin/asn1/make_oidtable $(ASN_BUILT_FILES:.asn=.h) $(ASN_SOURCE_FILES:.asn=.h) $(TESTS_ENVIRONTMENT_DEPS)
	TEST_LOG_NAME=`basename "$@"` \
		TEST_LOG_DIR=`dirname "$@"` \
		$(TESTS_ENVIRONMENT) \
		./bin/asn1/make_oidtable var/oidtable $(ASN_BUILT_FILES:.asn=.h) $(ASN_SOURCE_FILES:.asn=.h)

AM_CPPFLAGS += \
	-DOIDTABLE='(getenv("TESTS_TOP_BUILDDIR") == NULL ? "$(pkgdatadir)/oidtable" : "$(abs_top_builddir)/var/oidtable")'
