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
bin_to_six_SOURCES = bin_to_six.c prencode.c
six_to_bin_SOURCES = six_to_bin.c prencode.c
six2hex_SOURCES = six2hex.c prencode.c
whatsfcs_SOURCES = whatsfcs.c prencode.c
make_TA_SOURCES = make_TA.c
encode_oid_SOURCES = encode-oid.c
makeLTAtest_SOURCES = makeLTAtest.c
checkLTAtest_SOURCES = checkLTAtest.c

EXTRA_DIST = test_casn_random_driver.sh
