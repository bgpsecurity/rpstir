#
bin_PROGRAMS = create_object gen_hash

AM_CFLAGS = -g -Wall -DDEBUG -I../../cg/asn -I../../cg/asn_gen -I../../cg/casn

AM_LDFLAGS = $(LIBS)
LDADD = ../../proto/librpki.a ../../roa-lib/libroa.a ../../cg/asn/libasn.a \
	../../cg/casn/libcasn.a ../../utils/libutils.a

create_object_SOURCES = \
	create_cert.c \
	create_cert.h \
	create_crl.c \
	create_crl.h \
	create_manifest.c \
	create_manifest.h \
	create_object.c \
	create_object.h \
	create_roa.c \
	create_roa.h \
	create_utils.c \
	obj_err.h \
	sign_object.c

gen_hash_SOURCES = gen_hash.c

EXTRA_DIST = \
	certs.conf \
	create_objects.py \
	crl.conf \
	generic_allocate.py \
	roa.conf \
	rpkirepo.py \
	testbed_create.py \
	test.ini
