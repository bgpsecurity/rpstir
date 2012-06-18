noinst_LIBRARIES += lib/casn/libcasn.a

lib_casn_libcasn_a_SOURCES = \
	asn.h \
	asn_error.h \
	asn_flags.h \
	casn.c casn.h \
	casn_bit.c \
	casn_bits.c \
	casn_copy_diff.c \
	casn_dump.c \
	casn_error.c \
	casn_file_ops.c \
	casn_num.c \
	casn_objid.c \
	casn_other.c \
	casn_real.c \
	casn_time.c

lib_casn_libcasn_a_CFLAGS = -g -Wall -DINTEL

#lib_casn_libcasn_a_CPPFLAGS = # TODO
