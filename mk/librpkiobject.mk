noinst_LIBRARIES += lib/rpki-object/librpkiobject.a

LDADD_LIBRPKIOBJECT = \
	lib/rpki-object/librpkiobject.a \
	$(LDADD_LIBRPKIASN1)

lib_rpki_object_librpkiobject_a_SOURCES = \
	lib/rpki-object/certificate.c \
	lib/rpki-object/certificate.h \
	lib/rpki-object/cms/cms.c \
	lib/rpki-object/cms/cms.h \
	lib/rpki-object/signature.c \
	lib/rpki-object/signature.h
