noinst_PROGRAMS += lib/casn/asn_gen/asn_gen

lib_casn_asn_gen_asn_gen_CFLAGS = \
	-Wall \
	-g

lib_casn_asn_gen_asn_gen_CPPFLAGS = \
	-DCONSTRAINTS \
	-DINTEL \
	-Dasn_constr_id=casn_constr_id \
	-Dasn_hdr_id=casn_hdr_id \
	-Dconstruct=cconstruct \
	-Ddo_hdr=cdo_hdr \
	-Ilib/casn/asn_gen

lib_casn_asn_gen_asn_gen_SOURCES = \
	lib/casn/asn_gen/asn.h \
	lib/casn/asn_gen/asn_flags.h \
	lib/casn/asn_gen/asn_gen.c \
	lib/casn/asn_gen/asn_gen.h \
	lib/casn/asn_gen/asn_java.c \
	lib/casn/asn_gen/asn_obj.h \
	lib/casn/asn_gen/asn_pproc.c \
	lib/casn/asn_gen/asn_pprocx.c \
	lib/casn/asn_gen/asn_read.c \
	lib/casn/asn_gen/asn_tabulate.c \
	lib/casn/asn_gen/asn_timedefs.h \
	lib/casn/asn_gen/casn_constr.c \
	lib/casn/asn_gen/casn_hdr.c

.asn.c: lib/casn/asn_gen/asn_gen
	./lib/casn/asn_gen/asn_gen -c $<

.asn.h: lib/casn/asn_gen/asn_gen
	./lib/casn/asn_gen/asn_gen -c $<


noinst_LIBRARIES += lib/casn/libcasn.a

lib_casn_libcasn_a_CFLAGS = -g -Wall -DINTEL

#lib_casn_libcasn_a_CPPFLAGS = # TODO

lib_casn_libcasn_a_SOURCES = \
	asn.c \
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
