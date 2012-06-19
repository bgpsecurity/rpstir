noinst_PROGRAMS += lib/casn/asn_gen/asn_gen

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

lib_casn_libcasn_a_CPPFLAGS = \
	-DINTEL

lib_casn_libcasn_a_SOURCES = \
	lib/casn/asn.c \
	lib/casn/asn.h \
	lib/casn/asn_error.h \
	lib/casn/asn_flags.h \
	lib/casn/casn.c \
	lib/casn/casn.h \
	lib/casn/casn_bit.c \
	lib/casn/casn_bits.c \
	lib/casn/casn_copy_diff.c \
	lib/casn/casn_dump.c \
	lib/casn/casn_error.c \
	lib/casn/casn_file_ops.c \
	lib/casn/casn_num.c \
	lib/casn/casn_objid.c \
	lib/casn/casn_other.c \
	lib/casn/casn_real.c \
	lib/casn/casn_time.c


check_PROGRAMS += tests/subsystem/casn/test_casn_random


dist_check_SCRIPTS += tests/subsystem/casn/test_casn_random_driver.sh
