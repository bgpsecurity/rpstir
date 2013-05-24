AUTOMAKE_OPTIONS = \
	1.6 \
	foreign \
	subdir-objects \
	-Wall

ACLOCAL_AMFLAGS = -I build-aux -I m4


include mk/dirs.mk

include mk/flags.mk


## Lists of all files to be generated from .in files by make.
## The first list is for normal files, the second is for files that should be
## executable. NOTE: neither list can contain macros (variable). They MUST be
## lists of hardcoded filenames.
MK_SUBST_FILES =
MK_SUBST_FILES_EXEC =

## Lists of all .asn files. The first list is for generated .asn files, the
## second is for distributed sources.
ASN_BUILT_FILES =
ASN_SOURCE_FILES =

## Directories to remove during make clean.
CLEANDIRS =

## Files to copy from srcdir to builddir at the beginning of a build.
COPYFILES =

## Files in $(pkglibexecdir) that should have symlinks in $(bindir).
## E.g. the value "foo" would create a symlink $(bindir)/$(PACKAGE_NAME)-foo
## pointing to $(pkglibexecdir)/foo.
PACKAGE_NAME_BINS =

BUILT_SOURCES =
CLEANFILES =
EXTRA_DIST =
TESTS =
bin_PROGRAMS =
bin_SCRIPTS =
check_DATA =
check_LIBRARIES =
check_PROGRAMS =
check_SCRIPTS =
dist_bin_SCRIPTS =
dist_doc_DATA =
dist_man_MANS =
dist_noinst_DATA =
dist_pkgdata_DATA =
dist_sysconf_DATA =
examples_DATA =
noinst_DATA =
noinst_LIBRARIES =
noinst_PROGRAMS =
pkgdata_DATA =
pkglibexec_PROGRAMS =
pkglibexec_SCRIPTS =


## The test environment can be used by any of the other makefiles, so it comes
## first.
include mk/tests-environment.mk

## Library makefiles must be ordered by dependencies, lowest level library to
## highest.
include mk/libtest.mk
include mk/libutil.mk
include mk/libconfiglib.mk
include mk/libconfig.mk
include mk/libcasn.mk
include mk/librpkiasn1.mk
include mk/librpkiobject.mk
include mk/libdb.mk
include mk/librpkirtr.mk
include mk/librpki.mk

## "Normal" makefiles shouldn't depend on one another, so are in alphabetical
## order.
include mk/asn1.mk
include mk/config.mk
include mk/doxygen.mk
include mk/oidtable.mk
include mk/rpki-local-ta.mk
include mk/rpki-object.mk
include mk/rpki-rsync.mk
include mk/rpki-rtr.mk
include mk/rpki-statistics.mk
include mk/rpki.mk
include mk/testbed.mk
include mk/top.mk

## "Processor" makefiles come at the end because they sometimes need to
## evaluate macros from the above makefiles.
include mk/asn-files.mk
include mk/cleandirs.mk
include mk/copyfiles.mk
include mk/package-name-bins.mk
include mk/subst-files.mk
