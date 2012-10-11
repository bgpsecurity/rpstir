check_SCRIPTS += tests/system/testbed/src/create_objects.py
MK_SUBST_FILES_EXEC += tests/system/testbed/src/create_objects.py
tests/system/testbed/src/create_objects.py: $(srcdir)/tests/system/testbed/src/create_objects.py.in

check_SCRIPTS += tests/system/testbed/src/generic_allocate.py
MK_SUBST_FILES_EXEC += tests/system/testbed/src/generic_allocate.py
tests/system/testbed/src/generic_allocate.py: $(srcdir)/tests/system/testbed/src/generic_allocate.py.in

check_SCRIPTS += tests/system/testbed/src/rpkirepo.py
MK_SUBST_FILES_EXEC += tests/system/testbed/src/rpkirepo.py
tests/system/testbed/src/rpkirepo.py: $(srcdir)/tests/system/testbed/src/rpkirepo.py.in

check_SCRIPTS += tests/system/testbed/src/testbed_create.py
MK_SUBST_FILES_EXEC += tests/system/testbed/src/testbed_create.py
tests/system/testbed/src/testbed_create.py: $(srcdir)/tests/system/testbed/src/testbed_create.py.in


dist_check_DATA += \
	tests/system/testbed/src/certs.conf \
	tests/system/testbed/src/crl.conf \
	tests/system/testbed/src/roa.conf \
	tests/system/testbed/src/test.ini

EXTRA_DIST += \
	doc/testbed.txt
