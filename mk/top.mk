## Makefile for files that don't really belong to any other makefile, e.g. top-
## level files.

EXTRA_DIST += \
	autogen.sh \
	etc/version-server-ca.pem \
	ChangeLog \
	INSTRUCTIONS \
	LICENSE \
	README

pkgdata_DATA += etc/envir.setup
MK_SUBST_FILES += etc/envir.setup
etc/envir.setup: $(srcdir)/etc/envir.setup.in

examples_DATA += etc/rpstir.conf
MK_SUBST_FILES += etc/rpstir.conf
etc/rpstir.conf: $(srcdir)/etc/rpstir.conf.in

dist_doc_DATA += \
	doc/glossary.txt

dist_noinst_DATA += \
	doc/api.txt
