#
# Makefile for test cases
#
# $Id: Makefile 535 2008-06-20 18:57:43Z gardiner $
#
# ***** BEGIN LICENSE BLOCK *****
#  
#  BBN Address and AS Number PKI Database/repository software
#  Version 3.0-beta
#  
#  US government users are permitted unrestricted rights as
#  defined in the FAR.  
# 
#  This software is distributed on an "AS IS" basis, WITHOUT
#  WARRANTY OF ANY KIND, either express or implied.
# 
#  Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.  All Rights Reserved.
# 
#  Contributor(s):  Brenton Kohler
# 
# ***** END LICENSE BLOCK *****

AM_CFLAGS = -g -I../cg/asn -I../cg/asn_gen -I../cg/casn -Wall -I../roa-lib
bin_PROGRAMS=make_test_cert make_test_crl make_test_roa make_test_manifest  gen_test_key cert_validate

LDADD = ../roa-lib/libroa.a ../cg/asn/libasn.a ../cg/casn/libcasn.a ../utils/libutils.a

make_test_cert_SOURCES = make_test_cert.c adjustTime.c
make_test_cert_LDFLAGS = -lpthread $(LIBS)
make_test_crl_SOURCES = make_test_crl.c adjustTime.c
make_test_crl_LDFLAGS = -lpthread $(LIBS)
make_test_roa_SOURCES = make_test_roa.c
make_test_roa_LDFLAGS = -lpthread $(LIBS)
make_test_manifest_SOURCES = make_test_manifest.c adjustTime.c
make_test_manifest_LDFLAGS = -lpthread $(LIBS)
gen_test_key_SOURCES = gen_test_key.c
gen_test_key_LDFLAGS = -lpthread $(LIBS)
cert_validate_SOURCES = cert_validate.c
cert_validate_LDFLAGS = -lpthread $(LIBS)

EXTRA_DIST = \
	$(filter-out C.raw,$(wildcard *.p15 *.raw false*)) C.orig \
	certpattern \
	conformance \
	makeall \
	makecerts \
	makecrls \
	makekeys \
	makemanifests \
	makeroas \
	makeC* \
	makeL* \
	makeM* \
	print-cert-addrs.sh \
	queryIgnoreAll \
	rfc3779 \
	runtAll.sh \
	runt.sh \
	t?-?_* \
	test1.log \
	testall.sh \
	tools

CLEANFILES = \
	C.raw $(filter-out false%,$(wildcard *.man *.roa *.crl *.cer))

clean-local:
	rm -rf C1 C2 EEcertificates
