#ifndef __CERT_CHECK_H
#define __CERT_CHECK_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <openssl/x509.h> 
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pem.h>

X509 *x509_from_file(char *);
void print_key_usage(X509 *);
void print_extended_key_usage(X509 *);
void print_flags(X509 *);
int ca_check(X509 *);
int ee_check(X509 *);
int ta_check(X509 *);
void x509v3_load_extensions(X509 *x);
int rescert_version_chk(X509 *, unsigned int);
int rescert_profile_chk(X509 *, unsigned int);
int rescert_basic_constraints_chk(X509 *, unsigned int);
int rescert_ski_chk(X509 *, unsigned int);
int rescert_aki_chk(X509 *, unsigned int);
int rescert_key_usage_chk(X509 *, unsigned int);
int rescert_crldp_chk(X509 *, unsigned int);
int rescert_aia_chk(X509 *, unsigned int);
int rescert_sia_chk(X509 *, unsigned int);
int rescert_cert_policy_chk(X509 *, unsigned int);
int rescert_ip_asnum_chk(X509 *, unsigned int);
int rescert_ip_resources_chk(X509 *, unsigned int);
int rescert_as_resources_chk(X509 *, unsigned int);
int rescert_crit_ext_chk(X509_EXTENSION *);
int rescert_criticals_chk(X509 *, unsigned int);
static int res_nid_cmp(int *, int *);
void debug_chk_printf(char *str, int val, int cert_type);


#define TRUE 1
#define FALSE 0

#define UNK_CERT 0
#define CA_CERT 1
#define EE_CERT 2 
#define TA_CERT 3

#endif
