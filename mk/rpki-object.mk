bin_PROGRAMS += bin/rpki-object/add_cms_cert

bin_rpki_object_add_cms_cert_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/add_cms_cert_no_check

bin_rpki_object_add_cms_cert_no_check_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/add_key_info

bin_rpki_object_add_key_info_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/check_signature

bin_rpki_object_check_signature_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/extractCMScert

bin_rpki_object_extractCMScert_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/extractPubKeyInfo

bin_rpki_object_extractPubKeyInfo_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/extractSIA

bin_rpki_object_extractSIA_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/extractValidityDate

bin_rpki_object_extractValidityDate_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/fix_manifest

bin_rpki_object_fix_manifest_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/gen_key


bin_PROGRAMS += bin/rpki-object/get_sernum

bin_rpki_object_get_sernum_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/loadkey

bin_rpki_object_loadkey_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/put_sernum

bin_rpki_object_put_sernum_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/put_sia

bin_rpki_object_put_sia_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/put_subj

bin_rpki_object_put_subj_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/read_roa

bin_rpki_object_read_roa_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/set_cert_ski

bin_rpki_object_set_cert_ski_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/sign_cert

bin_rpki_object_sign_cert_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/sign_cms

bin_rpki_object_sign_cms_LDADD = \
	$(LDADD_LIBRPKIASN1)


bin_PROGRAMS += bin/rpki-object/update_cert

bin_rpki_object_update_cert_LDADD = \
	$(LDADD_LIBRPKIASN1)
