#
# Makefile for asn.1 tools
#
# $Id: Makefile 1135 2010-05-24 13:17:17Z achi $
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

bin_PROGRAMS=test_casn_random dump rr bin_to_six six_to_bin six2hex \
	loadkey gen_key whatsfcs make_oidtable make_TA set_cert_ski  \
	sign_cert add_key_info read_roa encode-oid dumpasn1 dump_smart \
	extractCMScert add_cms_cert test_cert makeLTAtest checkLTAtest \
        dumpIPAddr update_cert extractPubKeyInfo get_sernum put_sernum \
	extractSIA extractValidityDate fix_manifest check_signature \
        put_subj put_sia

AM_CFLAGS = -g -Wall -I../asn -I../asn_gen -I../casn -I../../roa-lib \
	-I../../proto -I../../utils

AM_CPPFLAGS = $(DEPS_CFLAGS)

LDADD = ../asn/libasn.a ../casn/libcasn.a ../../utils/libutils.a

test_casn_random_SOURCES = test_casn_random.c 
dump_SOURCES = dump.c asn.c asn_dump.c util.c asn.h
rr_SOURCES = rr.c md2.c asn.c asn.h
bin_to_six_SOURCES = bin_to_six.c prencode.c
six_to_bin_SOURCES = six_to_bin.c prencode.c
six2hex_SOURCES = six2hex.c prencode.c
loadkey_SOURCES = loadkey.c
loadkey_LDFLAGS = $(LIBS)
gen_key_SOURCES = gen_key.c
gen_key_LDFLAGS = $(LIBS)
whatsfcs_SOURCES = whatsfcs.c prencode.c
make_oidtable_SOURCES = make_oidtable.c
make_TA_SOURCES = make_TA.c roa.h
make_TA_LDFLAGS = $(LIBS)
set_cert_ski_SOURCES = set_cert_ski.c
set_cert_ski_LDFLAGS = $(LIBS)
sign_cert_SOURCES = sign_cert.c
sign_cert_LDFLAGS = $(LIBS)
add_key_info_SOURCES = add_key_info.c
add_key_info_LDFLAGS = $(LIBS)
read_roa_SOURCES = read_roa.c
read_roa_LDFLAGS = $(LIBS)
encode_oid_SOURCES = encode-oid.c
dumpasn1_SOURCES = dumpasn1.c
dump_smart_SOURCES = dump_smart.c
dump_smart_LDFLAGS = $(LIBS)
extractCMScert_SOURCES = extractCMScert.c
extractCMScert_LDFLAGS = $(LIBS)
add_cms_cert_SOURCES = add_cms_cert.c
add_cms_cert_LDFLAGS = $(LIBS)
test_cert_SOURCES = test_cert.c
test_cert_LDFLAGS = $(LIBS)
makeLTAtest_SOURCES = makeLTAtest.c
makeLTAtest_LDFLAGS = $(LIBS)
checkLTAtest_SOURCES = checkLTAtest.c
checkLTAtest_LDFLAGS = $(LIBS)
dumpIPAddr_SOURCES = dumpIPAddr.c
dumpIPAddr_LDFLAGS = $(LIBS)
update_cert_SOURCES = update_cert.c
update_cert_LDFLAGS = $(LIBS)
extractPubKeyInfo_SOURCES = extractPubKeyInfo.c
extractPubKeyInfo_LDFLAGS = $(LIBS)
get_sernum_SOURCES = get_sernum.c
get_sernum_LDFLAGS = $(LIBS)
put_sernum_SOURCES = put_sernum.c
put_sernum_LDFLAGS = $(LIBS)
put_subj_SOURCES = put_subj.c
put_subj_LDFLAGS = $(LIBS)
put_sia = put_sia.c
extractSIA_SOURCES = extractSIA.c
extractValidityDate_SOURCES = extractValidityDate.c
fix_manifest_SOURCES = fix_manifest.c
fix_manifest_LDFLAGS = $(LIBS)
check_signature_SOURCES = check_signature.c
check_signature_LDFLAGS = $(LIBS)
