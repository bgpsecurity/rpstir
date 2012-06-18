lib_rpki_asn1_librpkiasn1_a_ASN1_SOURCES = \
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

lib_rpki_asn1_librpkiasn1_a_ASN1_C = \
	lib/rpki-asn1/Algorithms.c \
	lib/rpki-asn1/blob.c \
	lib/rpki-asn1/certificate.c \
	lib/rpki-asn1/crlv2.c \
	lib/rpki-asn1/extensions.c \
	lib/rpki-asn1/keyfile.c \
	lib/rpki-asn1/manifest.c \
	lib/rpki-asn1/name.c \
	lib/rpki-asn1/orname.c \
	lib/rpki-asn1/privkey.c \
	lib/rpki-asn1/roa.c \
	lib/rpki-asn1/serial_number.c

lib_rpki_asn1_librpkiasn1_a_ASN1_H = \
	lib/rpki-asn1/Algorithms.h \
	lib/rpki-asn1/blob.h \
	lib/rpki-asn1/certificate.h \
	lib/rpki-asn1/crlv2.h \
	lib/rpki-asn1/extensions.h \
	lib/rpki-asn1/keyfile.h \
	lib/rpki-asn1/manifest.h \
	lib/rpki-asn1/name.h \
	lib/rpki-asn1/orname.h \
	lib/rpki-asn1/privkey.h \
	lib/rpki-asn1/roa.h \
	lib/rpki-asn1/serial_number.h

CLEANFILES += $(lib_rpki_asn1_librpkiasn1_a_ASN1_C)
CLEANFILES += $(lib_rpki_asn1_librpkiasn1_a_ASN1_H)

BUILT_SOURCES += $(lib_rpki_asn1_librpkiasn1_a_ASN1_H)

noinst_LIBRARIES += lib/rpki-asn1/librpkiasn1.a

lib_rpki_asn1_librpkiasn1_a_CFLAGS = -g -Wall

lib_rpki_asn1_librpkiasn1_a_SOURCES = \
	$(lib_rpki_asn1_librpkiasn1_a_ASN1_SOURCES) \
	lib/rpki-asn1/CertificateToBeSignedConstraint.c \
	lib/rpki-asn1/CertificateRevocationListToBeSignedConstraint.c

nodist_lib_rpki_asn1_librpkiasn1_a_SOURCES = \
	$(lib_rpki_asn1_librpkiasn1_a_ASN1_C) \
	$(lib_rpki_asn1_librpkiasn1_a_ASN1_H)
