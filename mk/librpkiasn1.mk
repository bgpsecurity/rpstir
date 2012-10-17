lib_rpki_asn1_librpkiasn1_a_ASN1 = \
	lib/rpki-asn1/Algorithms.asn \
	lib/rpki-asn1/blob.asn \
	lib/rpki-asn1/certificate.asn \
	lib/rpki-asn1/crlv2.asn \
	lib/rpki-asn1/extensions.asn \
	lib/rpki-asn1/keyfile.asn \
	lib/rpki-asn1/manifest.asn \
	lib/rpki-asn1/name.asn \
	lib/rpki-asn1/orname.asn \
	lib/rpki-asn1/privkey.asn \
	lib/rpki-asn1/roa.asn \
	lib/rpki-asn1/serial_number.asn

ASN_SOURCE_FILES += $(lib_rpki_asn1_librpkiasn1_a_ASN1)

noinst_LIBRARIES += lib/rpki-asn1/librpkiasn1.a

LDADD_LIBRPKIASN1 = \
	lib/rpki-asn1/librpkiasn1.a \
	$(LDADD_LIBCASN)

lib_rpki_asn1_librpkiasn1_a_SOURCES = \
	lib/rpki-asn1/CertificateToBeSignedConstraint.c \
	lib/rpki-asn1/CertificateRevocationListToBeSignedConstraint.c

nodist_lib_rpki_asn1_librpkiasn1_a_SOURCES = \
	$(lib_rpki_asn1_librpkiasn1_a_ASN1:.asn=.c) \
	$(lib_rpki_asn1_librpkiasn1_a_ASN1:.asn=.h)


check_PROGRAMS += tests/subsystem/rpki-asn1/test_casn_random

tests_subsystem_rpki_asn1_test_casn_random_LDADD = \
	$(LDADD_LIBRPKIASN1)


dist_check_SCRIPTS += tests/subsystem/rpki-asn1/test_casn_random_driver.sh
