pkgdata_DATA += var/oidtable
CLEANFILES += var/oidtable

var_oidtable_ASN1 = \
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

var/oidtable: ./bin/asn1/make_oidtable $(var_oidtable_ASN1)
	./bin/asn1/make_oidtable $(var_oidtable_ASN1) var/oidtable
