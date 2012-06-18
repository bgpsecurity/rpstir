noinst_PROGRAMS += bin/asn1/asn_gen/asn_gen

bin_asn1_asn_gen_asn_gen_CFLAGS = -g -Wall -DINTEL -Dconstruct=cconstruct -Ddo_hdr=cdo_hdr \
	-Dasn_constr_id=casn_constr_id \
	-Dasn_hdr_id=casn_hdr_id -DCONSTRAINTS -I.

bin_asn1_asn_gen_asn_gen_SOURCES = \
	bin/asn1/asn_gen/asn.h \
	bin/asn1/asn_gen/asn_flags.h \
	bin/asn1/asn_gen/asn_gen.c \
	bin/asn1/asn_gen/asn_gen.h \
	bin/asn1/asn_gen/asn_java.c \
	bin/asn1/asn_gen/asn_obj.h \
	bin/asn1/asn_gen/asn_pproc.c \
	bin/asn1/asn_gen/asn_pprocx.c \
	bin/asn1/asn_gen/asn_read.c \
	bin/asn1/asn_gen/asn_tabulate.c \
	bin/asn1/asn_gen/asn_timedefs.h \
	bin/asn1/asn_gen/casn_constr.c \
	bin/asn1/asn_gen/casn_hdr.c

.asn.c: bin/asn1/asn_gen/asn_gen
	./bin/asn1/asn_gen/asn_gen -c $<

.asn.h: bin/asn1/asn_gen/asn_gen
	./bin/asn1/asn_gen/asn_gen -c $<
