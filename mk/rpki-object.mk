pkglibexec_PROGRAMS += bin/rpki-object/add_cms_cert

bin_rpki_object_add_cms_cert_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


pkglibexec_PROGRAMS += bin/rpki-object/add_cms_cert_no_check

bin_rpki_object_add_cms_cert_no_check_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


pkglibexec_PROGRAMS += bin/rpki-object/add_key_info

bin_rpki_object_add_key_info_LDADD = \
	$(LDADD_LIBRPKIOBJECT)

dist_man_MANS += doc/add_key_info.1


pkglibexec_PROGRAMS += bin/rpki-object/check_signature

bin_rpki_object_check_signature_LDADD = \
	$(LDADD_LIBRPKIOBJECT)

dist_man_MANS += doc/check_signature.1


pkglibexec_PROGRAMS += bin/rpki-object/create_object/create_object

bin_rpki_object_create_object_create_object_SOURCES = \
	bin/rpki-object/create_object/create_cert.c \
	bin/rpki-object/create_object/create_cert.h \
	bin/rpki-object/create_object/create_crl.c \
	bin/rpki-object/create_object/create_crl.h \
	bin/rpki-object/create_object/create_manifest.c \
	bin/rpki-object/create_object/create_manifest.h \
	bin/rpki-object/create_object/create_object.c \
	bin/rpki-object/create_object/create_object.h \
	bin/rpki-object/create_object/create_roa.c \
	bin/rpki-object/create_object/create_roa.h \
	bin/rpki-object/create_object/create_utils.c \
	bin/rpki-object/create_object/obj_err.h \
	bin/rpki-object/create_object/sign_object.c

bin_rpki_object_create_object_create_object_LDADD = \
	$(LDADD_LIBRPKI)

dist_templates_DATA = \
	var/templates/*

dist_check_SCRIPTS += \
	bin/rpki-object/create_object/tests/empty_manifest.sh

CLEANDIRS += \
	bin/rpki-object/create_object/tests/empty_manifest

TESTS += \
	bin/rpki-object/create_object/tests/empty_manifest.sh


pkglibexec_PROGRAMS += bin/rpki-object/extractCMScert

bin_rpki_object_extractCMScert_LDADD = \
	$(LDADD_LIBRPKIASN1)


pkglibexec_PROGRAMS += bin/rpki-object/extractPubKeyInfo

bin_rpki_object_extractPubKeyInfo_LDADD = \
	$(LDADD_LIBRPKIASN1)


pkglibexec_PROGRAMS += bin/rpki-object/extractSIA

bin_rpki_object_extractSIA_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


pkglibexec_PROGRAMS += bin/rpki-object/extractValidityDate

bin_rpki_object_extractValidityDate_LDADD = \
	$(LDADD_LIBRPKIASN1)


pkglibexec_PROGRAMS += bin/rpki-object/fix_manifest

bin_rpki_object_fix_manifest_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


pkglibexec_PROGRAMS += bin/rpki-object/gen_hash

bin_rpki_object_gen_hash_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


pkglibexec_PROGRAMS += bin/rpki-object/gen_key

bin_rpki_object_gen_key_LDADD = \
	$(LDADD_LIBUTIL)

dist_man_MANS += doc/gen_key.1


pkglibexec_PROGRAMS += bin/rpki-object/get_sernum

bin_rpki_object_get_sernum_LDADD = \
	$(LDADD_LIBRPKIASN1)


pkglibexec_PROGRAMS += bin/rpki-object/loadkey

bin_rpki_object_loadkey_LDADD = \
	$(LDADD_LIBRPKIASN1)


pkglibexec_PROGRAMS += bin/rpki-object/makeROA

bin_rpki_object_makeROA_LDADD = \
	$(LDADD_LIBRPKI)


pkglibexec_PROGRAMS += bin/rpki-object/make_manifest

bin_rpki_object_make_manifest_LDADD = \
	$(LDADD_LIBRPKIOBJECT)

dist_man_MANS += doc/make_manifest.1


pkglibexec_PROGRAMS += bin/rpki-object/make_roa

bin_rpki_object_make_roa_LDADD = \
	$(LDADD_LIBRPKIOBJECT)

dist_man_MANS += doc/make_roa.1


pkglibexec_PROGRAMS += bin/rpki-object/put_sernum

bin_rpki_object_put_sernum_LDADD = \
	$(LDADD_LIBRPKIASN1)


pkglibexec_PROGRAMS += bin/rpki-object/put_sia

bin_rpki_object_put_sia_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


pkglibexec_PROGRAMS += bin/rpki-object/put_subj

bin_rpki_object_put_subj_LDADD = \
	$(LDADD_LIBRPKIASN1)


pkglibexec_PROGRAMS += bin/rpki-object/read_roa

bin_rpki_object_read_roa_LDADD = \
	$(LDADD_LIBRPKIASN1)

dist_man_MANS += doc/read_roa.1


pkglibexec_PROGRAMS += bin/rpki-object/set_cert_ski

bin_rpki_object_set_cert_ski_LDADD = \
	$(LDADD_LIBRPKIASN1)


pkglibexec_PROGRAMS += bin/rpki-object/sign_cert

bin_rpki_object_sign_cert_LDADD = \
	$(LDADD_LIBRPKIOBJECT)

dist_man_MANS += doc/sign_cert.1


pkglibexec_PROGRAMS += bin/rpki-object/sign_cms

bin_rpki_object_sign_cms_LDADD = \
	$(LDADD_LIBRPKIOBJECT)


pkglibexec_PROGRAMS += bin/rpki-object/update_cert

bin_rpki_object_update_cert_LDADD = \
	$(LDADD_LIBRPKIOBJECT)
