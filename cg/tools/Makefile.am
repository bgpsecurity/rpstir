#
# Makefile for asn.1 tools
#
# $Id: Makefile 1135 2010-05-24 13:17:17Z achi $
#

bin_PROGRAMS=test_casn_random dump rr bin_to_six six_to_bin six2hex \
	loadkey gen_key whatsfcs make_oidtable make_TA set_cert_ski  \
	sign_cert add_key_info read_roa encode-oid dump_smart \
	extractCMScert add_cms_cert test_cert makeLTAtest checkLTAtest \
        dumpIPAddr update_cert extractPubKeyInfo get_sernum put_sernum \
	extractSIA extractValidityDate fix_manifest check_signature \
        put_subj put_sia add_cms_cert_no_check sign_cms

AM_CFLAGS = -g -Wall -I../asn -I../asn_gen -I../casn -I../../roa-lib \
	-I../../proto -I../../utils

AM_CPPFLAGS = $(DEPS_CFLAGS)

LDADD = ../asn/libasn.a ../casn/libcasn.a ../../utils/libutils.a

test_casn_random_SOURCES = test_casn_random.c 
dump_SOURCES = dump.c asn.c asn_dump.c util.c asn.h
rr_SOURCES = rr.c asn.c asn.h
bin_to_six_SOURCES = bin_to_six.c prencode.c
six_to_bin_SOURCES = six_to_bin.c prencode.c
six2hex_SOURCES = six2hex.c prencode.c
loadkey_SOURCES = loadkey.c
gen_key_SOURCES = gen_key.c
whatsfcs_SOURCES = whatsfcs.c prencode.c
make_oidtable_SOURCES = make_oidtable.c
make_TA_SOURCES = make_TA.c
set_cert_ski_SOURCES = set_cert_ski.c
sign_cert_SOURCES = sign_cert.c
sign_cms_SOURCES = sign_cms.c
add_key_info_SOURCES = add_key_info.c
read_roa_SOURCES = read_roa.c
encode_oid_SOURCES = encode-oid.c
dump_smart_SOURCES = dump_smart.c
extractCMScert_SOURCES = extractCMScert.c
add_cms_cert_SOURCES = add_cms_cert.c
add_cms_cert_no_check_SOURCES = add_cms_cert_no_check.c
test_cert_SOURCES = test_cert.c
makeLTAtest_SOURCES = makeLTAtest.c
checkLTAtest_SOURCES = checkLTAtest.c
dumpIPAddr_SOURCES = dumpIPAddr.c
update_cert_SOURCES = update_cert.c
extractPubKeyInfo_SOURCES = extractPubKeyInfo.c
get_sernum_SOURCES = get_sernum.c
put_sernum_SOURCES = put_sernum.c
put_subj_SOURCES = put_subj.c
put_sia_SOURCES = put_sia.c
extractSIA_SOURCES = extractSIA.c
extractValidityDate_SOURCES = extractValidityDate.c
fix_manifest_SOURCES = fix_manifest.c
check_signature_SOURCES = check_signature.c

EXTRA_DIST = convert-oidtable.sh test_casn_random_driver.sh
