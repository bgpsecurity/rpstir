pkgdata_DATA += etc/envir.setup
MK_SUBST_FILES += etc/envir.setup
etc/envir.setup: $(srcdir)/etc/envir.setup.in

examples_DATA += etc/rpstir.conf
MK_SUBST_FILES += etc/rpstir.conf
etc/rpstir.conf: $(srcdir)/etc/rpstir.conf.in

noinst_DATA += tests/test.include
MK_SUBST_FILES += tests/test.include
tests/test.include: $(srcdir)/tests/test.include.in
