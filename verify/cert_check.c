#include "cert_check.h"

X509 *
x509_from_file(char *file)
{
  FILE *cert_fp;
  X509 *x;

  cert_fp = NULL;
  x = NULL;

  cert_fp = fopen(file, "r");
  if (!cert_fp) {
    fprintf(stderr, "could not open [%s]\n", file);
    return(NULL);
  }

  x = PEM_read_X509(cert_fp, NULL, NULL, NULL);
  fclose(cert_fp);

  if (!x) {
    fprintf(stderr, "Error reading X509 cert from [%s]\n", file);
    return(NULL);
  } else {
    return(x);
  }
}

void
print_key_usage(X509 *x)
{
  /* STUB */
  printf("key_usage: 0x%0lx\n", x->ex_kusage);
}

void
print_extended_key_usage(X509 *x)
{
  /* STUB */
  printf("extended key_usage: 0x%0lx\n", x->ex_xkusage);
}

void
print_flags(X509 *x)
{
  /* STUB */
  printf("flags: 0x%0lx\n", x->ex_flags);
}

int
ta_check(X509 *x)
{
  unsigned long ta_flags = 0;
  unsigned long ta_kusage = 0;

  ta_flags = (EXFLAG_SET|EXFLAG_SS|EXFLAG_CA|EXFLAG_KUSAGE|EXFLAG_BCONS);
  ta_kusage = (KU_KEY_CERT_SIGN|KU_CRL_SIGN);

  if (x->ex_flags != ta_flags)
    return(FALSE);
  if (x->ex_kusage != ta_kusage)
    return(FALSE);

  if (x->ex_xkusage != 0)
    return(FALSE);
  if (x->ex_nscert != 0)
    return(FALSE);

  return(TRUE);
}

int 
ca_check(X509 *x) 
{
  unsigned long ca_flags = 0;
  unsigned long ca_kusage = 0;

  ca_flags = (EXFLAG_SET|EXFLAG_CA|EXFLAG_KUSAGE|EXFLAG_BCONS);
  ca_kusage = (KU_KEY_CERT_SIGN|KU_CRL_SIGN);

  if (x->ex_flags != ca_flags)
    return(FALSE);
  if (x->ex_kusage != ca_kusage)
    return(FALSE);

  if (x->ex_xkusage != 0)
    return(FALSE);
  if (x->ex_nscert != 0)
    return(FALSE);

  return(TRUE);
}

int 
ee_check(X509 *x) 
{
  unsigned long ee_flags = 0;
  unsigned long ee_kusage = 0;

  ee_flags = (EXFLAG_SET|EXFLAG_KUSAGE|EXFLAG_BCONS);
  ee_kusage = (KU_DIGITAL_SIGNATURE);

  if (x->ex_flags != ee_flags)
    return(FALSE);
  if (x->ex_kusage != ee_kusage)
    return(FALSE);

  if (x->ex_xkusage != 0)
    return(FALSE);

  if (x->ex_nscert != 0)
    return(FALSE);

  return(TRUE);
}

/**********************************************************
 * profile_check(X509 *, unsigned int cert_type)          *
 *  This function makes sure the required base elemets    *
 *  are present within the certificate.                   *
 *   cert_type can be one of CA_CERT, EE_CERT, TA_CERT    *
 *                                                        *
 *  Basic Constraints - critical MUST be present          *
 *    path length constraint MUST NOT be present          *
 *                                                        *
 *  Subject Key Identifier - non-critical MUST be present *
 *                                                        *
 *  Authority Key Identifier - non-crit MUST be present   *
 *    keyIdentifier - MUST be present except in TA's      *
 *      (TA versus EE,CA checks performed elsewhere)      *
 *    authorityCertIssuer - MUST NOT be present           *
 *    authorityCertSerialNumber - MUST NOT be present     *
 *                                                        *
 *  Key Usage - critical - MUST be present                *
 *    ({CA,EE} specific checks performed elsewhere)       *
 *    CA - keyCertSign and CRLSign only                   *
 *    EE - digitalSignature only                          *
 *                                                        *
 *  CRL Distribution Points - non-crit - MUST be present  *
 *                                                        *
 *  Authority Information Access - non-crit - MUST        *
 *     be present                                         *
 *    (in the case of TAs this SHOULD be omitted - this   *
 *    check performed elsewhere)                          * 
 *                                                        *
 *  Subject Information Access -                          *
 *    CA - non-critical - MUST be present                 *
 *    non-CA - MUST NOT be present                        *
 *      Will check for this elsewhere.                    *
 *                                                        *
 *  Certificate Policies - critical - MUST be present     *
 *    PolicyQualifiers - MUST NOT be used in this profile *
 *    OID Policy Identifier value: "1.3.6.1.5.5.7.14.2"   *
 *                                                        *
 *  Subject Alt Name - optional, not checked for          *
 *                                                        *
 *  IP Resources, AS Resources - critical - MUST have one *
 *   of these or both. In the case of one, if present     *
 *   marked as critical                                   *
 *********************************************************/

int
rescert_profile_chk(X509 *x, unsigned int cert_type)
{
  int ret;

  ret = TRUE; /* plenty of chances to change to FALSE :) */

  /* load the X509_st extension values */
  x509v3_load_extensions(x);

  ret = rescert_version_chk(x, cert_type);
#ifdef DEBUG
  debug_chk_printf("rescert_version_chk", ret, cert_type);
#endif
  if (ret != TRUE)
    return(ret);

  ret = rescert_basic_constraints_chk(x, cert_type);
#ifdef DEBUG
  debug_chk_printf("rescert_basic_constraints_chk", ret, cert_type);
#endif
  if (ret != TRUE)
    return(ret);

  ret = rescert_ski_chk(x, cert_type);
#ifdef DEBUG
  debug_chk_printf("rescert_ski_chk", ret, cert_type);
#endif
  if (ret != TRUE)
    return(ret);

  ret = rescert_aki_chk(x, cert_type);
#ifdef DEBUG
  debug_chk_printf("rescert_aki_chk", ret, cert_type);
#endif
  if (ret != TRUE)
    return(ret);

  ret = rescert_key_usage_chk(x, cert_type);
#ifdef DEBUG
  debug_chk_printf("rescert_key_usage_chk", ret, cert_type);
#endif
  if (ret != TRUE)
    return(ret);

  ret = rescert_crldp_chk(x, cert_type);
#ifdef DEBUG
  debug_chk_printf("rescert_crldp_chk", ret, cert_type);
#endif
  if (ret != TRUE)
    return(ret);

  ret = rescert_aia_chk(x, cert_type);
#ifdef DEBUG
  debug_chk_printf("rescert_aia_chk", ret, cert_type);
#endif
  if (ret != TRUE)
    return(ret);

  ret = rescert_sia_chk(x, cert_type);
#ifdef DEBUG
  debug_chk_printf("rescert_sia_chk", ret, cert_type);
#endif
  if (ret != TRUE)
    return(ret);

  ret = rescert_cert_policy_chk(x, cert_type);
#ifdef DEBUG
  debug_chk_printf("rescert_cert_policy_chk", ret, cert_type);
#endif
  if (ret != TRUE)
    return(ret);

  ret = rescert_ip_asnum_chk(x, cert_type);
#ifdef DEBUG
  debug_chk_printf("rescert_ip_asnum_chk", ret, cert_type);
#endif
  if (ret != TRUE)
    return(ret);

  ret = rescert_criticals_chk(x, cert_type);
#ifdef DEBUG
  debug_chk_printf("rescert_criticals_chk", ret, cert_type);
#endif
  if (ret != TRUE)
    return(ret);

#ifdef DEBUG
  if (ret == TRUE)
    printf("rescert_profile_chk returning true\n");
  else
    printf("rescert_profile_chk returning false\n");
#endif

  return(ret);
}

/*************************************************************
 * int rescert_version_chk(X509 *, unsigned int cert_type)   *
 *                                                           *
 *  we require v3 certs (which is value 2)                   *
 ************************************************************/
int
rescert_version_chk(X509 *x, unsigned int cert_type)
{
  long l;
  l = 0;
  l = X509_get_version(x);
  /* returns the value which is 2 to denote version 3 */

#ifdef DEBUG
  printf("rescert_version_check: version %lu\n", l + 1);
#endif
  if (l != 2)  /* see above: value of 2 means v3 */
    return(FALSE);
  else
    return(TRUE);
}

/*************************************************************
 * rescert_basic_constraints_chk(X509 *, unsigned int)       *
 *                                                           *
 *  Basic Constraints - critical MUST be present             *
 *    path length constraint MUST NOT be present             *
 *                                                           *
 * Whereas the Huston rescert sidr draft states that         *
 * basic Constraints must be present and must be marked crit *
 * RFC 2459 states that it SHOULD NOT be present for EE cert *
 *                                                           *
 * the certs that APNIC et al have been making have the      *
 * extension present but not marked critical in EE certs     *
 * sooo...                                                   *
 *    If it's a CA cert then it MUST be present and MUST     *
 *    be critical. If it's an EE cert then it MUST be         *
 *    present MUST NOT have the cA flag set and we don't care *
 *    if it's marked critical or not. awaiting word back from *
 *    better sources than I if this is correct.              *
 *                                                          *
 ************************************************************/
int
rescert_basic_constraints_chk(X509 *x, unsigned int cert_type)
{
  int i, basic_flag;
  int ex_nid;
  int ret;
  X509_EXTENSION *ex;
  BASIC_CONSTRAINTS *bs;
  unsigned long ta_flags, ta_kusage, ca_flags, ca_kusage, ee_flags, ee_kusage;

  basic_flag = 0;
  ret = TRUE;
  bs = NULL;
  ex = NULL;

  ta_flags = (EXFLAG_SET|EXFLAG_SS|EXFLAG_CA|EXFLAG_KUSAGE|EXFLAG_BCONS);
  ta_kusage = (KU_KEY_CERT_SIGN|KU_CRL_SIGN);
  ca_flags = (EXFLAG_SET|EXFLAG_CA|EXFLAG_KUSAGE|EXFLAG_BCONS);
  ca_kusage = (KU_KEY_CERT_SIGN|KU_CRL_SIGN);
  ee_flags = (EXFLAG_SET|EXFLAG_KUSAGE|EXFLAG_BCONS);
  ee_kusage = (KU_DIGITAL_SIGNATURE);

  if((x->ex_flags & EXFLAG_SET) == 0)
    x509v3_load_extensions(x);
  if ((x->ex_flags & EXFLAG_SET) == 0)
    return(FALSE);

  /* if cert_type == UNK_CERT try to figure out what we believe it to
     be from flags and kusage */
  if (cert_type == UNK_CERT) {
    if ( (x->ex_flags == ta_flags) && (x->ex_kusage == ta_kusage) )
      cert_type = TA_CERT;
    else if ( (x->ex_flags == ca_flags) && (x->ex_kusage == ca_kusage) )
      cert_type = CA_CERT;
    else if ( (x->ex_flags == ee_flags) && (x->ex_kusage == ee_flags) )
      cert_type = EE_CERT;
    else
      cert_type = UNK_CERT;
  }

  /* test the basic_constraints based against either an
     CA_CERT (cert authority), EE_CERT (end entity), or TA_CERT
     (trust anchor) as definied in the X509 Profile for
     resource certificates. */
  switch(cert_type) {

    case UNK_CERT:
#ifdef DEBUG
      /* getting here means we couldn't figure it out above.. */
      fprintf(stderr, "couldn't determine cert_type to test against\n");
#endif
      return(FALSE);
      break;

    case CA_CERT:
    case TA_CERT:
      /* Basic Constraints MUST be present, MUST be
         critical, cA boolean has to be set for CAs */ 
      for (i = 0; i < X509_get_ext_count(x); i++) {
        ex = X509_get_ext(x, i);
        ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

        if (ex_nid == NID_basic_constraints) {
          basic_flag++;
   
          if (!X509_EXTENSION_get_critical(ex)) {
#ifdef DEBUG
            fprintf(stderr, "[basic_const] CA_CERT: basic_constriaints NOT critical!\n");
#endif
            ret = FALSE;
            goto skip;
          }

          bs=X509_get_ext_d2i(x, NID_basic_constraints, NULL, NULL);                                
          if (!(bs->ca)) { 
#ifdef DEBUG
            fprintf(stderr, "[basic_const] testing for CA_CERT: cA boolean NOT set\n");
#endif
            ret = FALSE;
            goto skip;
          }

          if (bs->pathlen) { 
#ifdef DEBUG
            fprintf(stdout, "[basic_const] basic constraints pathlen present - profile violation\n");             
#endif
            ret = FALSE;
            goto skip;
          }                                                                                         

          BASIC_CONSTRAINTS_free(bs);
        }
     }  
     if (basic_flag == 0) {
#ifdef DEBUG
       fprintf(stderr, "[basic_const] basic_constraints not present\n");
#endif
       return(FALSE);
     } else if (basic_flag > 1) {
#ifdef DEBUG
       fprintf(stderr, "[basic_const] mutliple instances of extension\n");
#endif
       return(FALSE);
     } else {
       return(TRUE);
     }
     break; /* should never get to break */


    case EE_CERT:
      /* Basic Constraints MUST be present, we don't check that it 
         is marked critical, cA boolean should not be set 
         pathlen MUST NOT be present */ 

      for (i = 0; i < X509_get_ext_count(x); i++) {           
        ex = X509_get_ext(x, i);                              
        ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));  
                                                              
        if (ex_nid == NID_basic_constraints) {                
          basic_flag++;                                     
                                                              
          bs=X509_get_ext_d2i(x, NID_basic_constraints, NULL, NULL);           

          if ((bs->ca)) {                                                     
#ifdef DEBUG
            fprintf(stderr, "[basic_const] EE_CERT: cA boolean IS set\n");   
#endif
            ret = FALSE;
            goto skip;
          }
                                                              
          if (bs->pathlen) {                                                   
#ifdef DEBUG
            fprintf(stdout, "[basic_const] pathlen found, profile violation\n");
#endif
            ret = FALSE;
            goto skip;
          }                                                                    
                                                              
          BASIC_CONSTRAINTS_free(bs);                         
        }                                                     
        if (basic_flag == 0) {
#ifdef DEBUG
          fprintf(stderr, "[basic_const] extension not present\n");
#endif
          return(FALSE);
        } else if (basic_flag > 1) {
#ifdef DEBUG
          fprintf(stderr, "[basic_const] multiple instances of extension\n");
#endif
          return(FALSE);
        } else {
          return(TRUE);
        }
      break;
    }
  }
skip:
#ifdef DEBUG
  fprintf(stderr, "[basic_const] jump to return...\n");
#endif
  if (bs)
    BASIC_CONSTRAINTS_free(bs);
  return(ret);
} 

/*************************************************************
 * rescert_ski_chk(X509 *, unsigned int)                     *
 *                                                           *
 *  Subject Key Identifier - non-critical MUST be present    *
 *                                                           *
 *  We don't do anything with the cert_type as this is true  *
 *  of EE, CA, and TA certs in the resrouce cert profile     *
 ************************************************************/
int
rescert_ski_chk(X509 *x, unsigned int cert_type)
{

  int ski_flag;
  int i;
  int ex_nid;
  int ret;
  X509_EXTENSION *ex;

  ex = NULL;
  ski_flag = 0;
  ret = TRUE;

  if((x->ex_flags & EXFLAG_SET) == 0)
    x509v3_load_extensions(x);
  if ((x->ex_flags & EXFLAG_SET) == 0)
    return(FALSE);

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

    if (ex_nid == NID_subject_key_identifier) {
      ski_flag++; 
      if (X509_EXTENSION_get_critical(ex)) {
#ifdef DEBUG
        fprintf(stderr, "SKI marked as critical, profile violation\n");
#endif
        ret = FALSE;
        goto skip;
      }
    }
  }
  if (ski_flag == 0) {
#ifdef DEBUG
    fprintf(stderr, "[ski] ski extionsion missing\n");
#endif
    return(FALSE);
  } else if (ski_flag > 1) {
#ifdef DEBUG
    fprintf(stderr, "[ski] multiple instances of ski extension\n");
#endif
    return(FALSE);
  } else {
    return(TRUE);
  }
skip:
#ifdef DEBUG
  fprintf(stderr, "[ski]jump to return...\n");
#endif
  return(ret);
}

/*************************************************************
 * rescert_aki_chk(X509 *, unsigned int)                     *
 *                                                           *
 *  Authority Key Identifier - non-crit MUST be present      *
 *    keyIdentifier - MUST be present except in TA's         *
 *    authorityCertIssuer - MUST NOT be present              *
 *    authorityCertSerialNumber - MUST NOT be present        *
 *                                                           *
 ************************************************************/
int
rescert_aki_chk(X509 *x, unsigned int cert_type)
{
  int aki_flag;
  int i;
  int ex_nid;
  int ret;
  X509_EXTENSION *ex;
  AUTHORITY_KEYID *akid;
  unsigned long ta_flags, ta_kusage, ca_flags, ca_kusage, ee_flags, ee_kusage;  

  ret = TRUE;
  ex = NULL;
  akid = NULL;
  aki_flag = 0;
  
  if((x->ex_flags & EXFLAG_SET) == 0)
    x509v3_load_extensions(x);
  if ((x->ex_flags & EXFLAG_SET) == 0)
    return(FALSE); 
    
  ta_flags = (EXFLAG_SET|EXFLAG_SS|EXFLAG_CA|EXFLAG_KUSAGE|EXFLAG_BCONS);
  ta_kusage = (KU_KEY_CERT_SIGN|KU_CRL_SIGN);
  ca_flags = (EXFLAG_SET|EXFLAG_CA|EXFLAG_KUSAGE|EXFLAG_BCONS);
  ca_kusage = (KU_KEY_CERT_SIGN|KU_CRL_SIGN);
  ee_flags = (EXFLAG_SET|EXFLAG_KUSAGE|EXFLAG_BCONS);
  ee_kusage = (KU_DIGITAL_SIGNATURE);
        
  /* if cert_type == UNK_CERT try to figure out what we believe it to
     be from flags and kusage */
  if (cert_type == UNK_CERT) {
    if ( (x->ex_flags == ta_flags) && (x->ex_kusage == ta_kusage) )
      cert_type = TA_CERT;
    else if ( (x->ex_flags == ca_flags) && (x->ex_kusage == ca_kusage) )
      cert_type = CA_CERT;
    else if ( (x->ex_flags == ee_flags) && (x->ex_kusage == ee_flags) )
      cert_type = EE_CERT;
    else    
      cert_type = UNK_CERT;
  }       

  if (cert_type == UNK_CERT) {
#ifdef DEBUG
    fprintf(stderr, "[aki] could not determine cert type for tests\n");
#endif
    return(FALSE);
  }

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));
    
    if (ex_nid == NID_authority_key_identifier) {
      aki_flag++; 

      if (X509_EXTENSION_get_critical(ex)) {
#ifdef DEBUG
        fprintf(stderr, "[aki] critical, profile violation\n");
#endif
        ret = FALSE;
        goto skip;
      } 

      akid = X509_get_ext_d2i(x, NID_authority_key_identifier, NULL, NULL);
      if (!akid) {
#ifdef DEBUG
        fprintf(stderr, "[aki] could not load aki\n");
#endif
        return(FALSE);
      }

      /* Key Identifier sub field MUST be present in all certs except for
         self signed CA (aka TA) */
      if ( (!akid->keyid) && (cert_type != TA_CERT)) {
#ifdef DEBUG
        fprintf(stderr, "[aki] key identifier sub field not present\n");
#endif
        ret = FALSE;
        goto skip;
      } 

      if (akid->issuer) {
#ifdef DEBUG
        fprintf(stderr, 
                "[aki_chk] authorityCertIssuer is present = violation\n");
#endif
        ret = FALSE;
        goto skip;
      }

      if (akid->serial) {
#ifdef DEBUG
        fprintf(stderr, 
                "[aki_chk] authorityCertSerialNumber is present = violation\n");
#endif
        ret = FALSE;
        goto skip;
      }
    } 
  }

  if (akid)
    AUTHORITY_KEYID_free(akid);

  if (aki_flag == 0) {
#ifdef DEBUG
    fprintf(stderr, "[aki_chk] missing AKI extension\n");
#endif
    return(FALSE);
  } else if (aki_flag > 1) {
#ifdef DEBUG
    fprintf(stderr, "[aki_chk] duplicate AKI extensions\n");
#endif
    return(FALSE);
  } else {
    return(TRUE);
  } 

skip:
#ifdef DEBUG
  fprintf(stderr, "[ski]jump to return...\n");
#endif
  if (akid)
    AUTHORITY_KEYID_free(akid);
  return(ret);
} 


/*************************************************************
 * rescert_key_usage_chk(X509 *, unsigned int)               *
 *                                                           *
 *  Key Usage - critical - MUST be present                   *
 *    TA|CA - keyCertSign and CRLSign only                   *
 *    EE - digitalSignature only                             *
 *                                                           *
 ************************************************************/
int
rescert_key_usage_chk(X509 *x, unsigned int cert_type)
{
  int kusage_flag;
  int i;
  int ex_nid;
  int ret;
  X509_EXTENSION *ex;
  unsigned long ta_flags, ta_kusage, ca_flags, ca_kusage, ee_flags, ee_kusage;

  ta_flags = (EXFLAG_SET|EXFLAG_SS|EXFLAG_CA|EXFLAG_KUSAGE|EXFLAG_BCONS);
  ta_kusage = (KU_KEY_CERT_SIGN|KU_CRL_SIGN);
  ca_flags = (EXFLAG_SET|EXFLAG_CA|EXFLAG_KUSAGE|EXFLAG_BCONS);
  ca_kusage = (KU_KEY_CERT_SIGN|KU_CRL_SIGN);
  ee_flags = (EXFLAG_SET|EXFLAG_KUSAGE|EXFLAG_BCONS);
  ee_kusage = (KU_DIGITAL_SIGNATURE);

  kusage_flag = 0;

  if((x->ex_flags & EXFLAG_SET) == 0)
    x509v3_load_extensions(x);
  if ((x->ex_flags & EXFLAG_SET) == 0)
    return(FALSE);

  /* if cert_type == UNK_CERT try to figure out what we believe it to
     be from flags and kusage */
  if (cert_type == UNK_CERT) {
    if ( (x->ex_flags == ta_flags) && (x->ex_kusage == ta_kusage) )
      cert_type = TA_CERT;
    else if ( (x->ex_flags == ca_flags) && (x->ex_kusage == ca_kusage) )
      cert_type = CA_CERT;
    else if ( (x->ex_flags == ee_flags) && (x->ex_kusage == ee_flags) )
      cert_type = EE_CERT;
    else
      cert_type = UNK_CERT;
  }

  /* we've already checked the correct flags.  If it's anything other 
     than UNK_CERT we can go into the loop below to make sure key_usage
     is marked critical and that there's only one instance of it  */
  if (cert_type == UNK_CERT) {
#ifdef DEBUG
    fprintf(stderr, "[key_usage] incorrect Key Usage bits set\n");
#endif
    return(FALSE);
  }

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));
  
    if (ex_nid == NID_key_usage) {
      kusage_flag++;
      if (!X509_EXTENSION_get_critical(ex)) {
#ifdef DEBUG
        fprintf(stderr, "[kusage] not marked critical, violation\n");
#endif
        ret = FALSE;
        goto skip;
      } 

      /* I don't like that I'm depending upon other OpenSSL components
         for the populating of a parent structure for testing this,
         but running out of time and there's no KEY_USAGE_st and I
         don't have the time to parse the ASN1_BIT_STRING (probably 
         trivial but don't know it yet...). Check asn1/asn1.h for 
         struct asn1_string_st, x509v3/v3_bitst.c, and get the
         ASN1_BIT_STRING via usage=X509_get_ext_d2i(x, NID_key_usage,
         NULL, NULL) if we end up doing this correctly. 
         */
    }
  }

  if (kusage_flag == 0) {
#ifdef DEBUG
    fprintf(stderr, "[key_usage] missing Key Usage extension\n");
#endif
    return(FALSE);
  } else if (kusage_flag > 1) {
#ifdef DEBUG
    fprintf(stderr, "[key_usage] multiple key_usage extensions\n");
#endif
    return(FALSE);
  } else {
    return(TRUE);
  }

skip:
#ifdef DEBUG
  fprintf(stderr, "[key_usage] jump to...\n");
#endif
  return(ret);
}

/*************************************************************
 * rescert_crldp_chk(X509 *, unsigned int)                   *
 *                                                           *
 *  CRL Distribution Points - non-crit -                     *
 *  MUST be present unless the CA is self-signed (TA) in     *
 *  which case it MUST be omitted.                           *
 *                                                           *
 *  CRLissuer MUST be omitted                                *
 *  reasons MUST be omitted                                  *
 *                                                           * 
 ************************************************************/                                  
int
rescert_crldp_chk(X509 *x, unsigned int cert_type)
{

  int crldp_flag, uri_flag;
  int i;
  int ex_nid;
  int ret;
  STACK_OF(DIST_POINT) *crldp;
  DIST_POINT *dist_st;
  X509_EXTENSION *ex;
  GENERAL_NAME *gen_name;

  crldp = NULL;
  dist_st = NULL;
  gen_name = NULL;
  crldp_flag = uri_flag = 0;
  ret = TRUE;
 
  if((x->ex_flags & EXFLAG_SET) == 0)
    x509v3_load_extensions(x);
  if ((x->ex_flags & EXFLAG_SET) == 0)
    return(FALSE);

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));
  
    if (ex_nid == NID_crl_distribution_points) {
      crldp_flag++;
      if (cert_type == TA_CERT) {
#ifdef DEBUG
        fprintf(stderr, "[crldp] crldp found in self-signed cert\n");
#endif
        ret = FALSE;
        goto skip;
      }
      if (X509_EXTENSION_get_critical(ex)) {                 
#ifdef DEBUG
        fprintf(stderr, "[crldp] marked critical, violation\n");       
#endif
        ret = FALSE;                                          
        goto skip;                                            
      }                                                       

    }
  }

  if (crldp_flag == 0) {
    if (cert_type == TA_CERT) {  /* must be omitted if TA */
      ret = TRUE;
      goto skip;
    }
#ifdef DEBUG
    fprintf(stderr, "[crldp] missing crldp extension\n");
#endif
    return(FALSE);
  } else if (crldp_flag > 1) {
#ifdef DEBUG
    fprintf(stderr, "[crldp] multiple crldp extensions\n");
#endif
    return(FALSE);
  }

  /* we should be here if NID_crl_distribution_points was found,
     it was not marked critical, and there was only one instance of it.

     I think rob's code is doing this right so I'm lifting his
     checks from rcynic.c */

  crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
  if (!crldp) {
#ifdef DEBUG
    fprintf(stderr, "[crldp] could not retrieve crldp extension\n");
#endif
    return(FALSE);
  } else if (sk_DIST_POINT_num(crldp) != 1) {
#ifdef DEBUG
    fprintf(stderr, "[crldp] incorrect number of STACK_OF(DIST_POINT)\n");
#endif
    ret = FALSE;
    goto skip;
  }

  dist_st = sk_DIST_POINT_value(crldp, 0);
  if (dist_st->reasons || dist_st->CRLissuer || !dist_st->distpoint 
      || dist_st->distpoint->type != 0) {
#ifdef DEBUG
    fprintf(stderr, "[crldp] incorrect crldp sub fields\n");
#endif
    ret = FALSE;
    goto skip;
  } 

  for (i=0; i < sk_GENERAL_NAME_num(dist_st->distpoint->name.fullname); i++) {
    gen_name = sk_GENERAL_NAME_value(dist_st->distpoint->name.fullname, i);
    if (!gen_name) {
#ifdef DEBUG
      fprintf(stderr, "[crldp] error retrieving distribution point name\n");
#endif
      ret = FALSE;
      goto skip; 
    }
    /* all of the general names must be of type URI */
    if (gen_name->type != GEN_URI) {
#ifdef DEBUG
      fprintf(stderr, "[crldp] general name of non GEN_URI type found\n");
#endif
      ret = FALSE;
      goto skip;
    }

    if (!strncasecmp((const char *)gen_name->d.uniformResourceIdentifier->data,
                     (const char *)"rsync://", sizeof("rsync://") -1))  {
      /* printf("uri: %s\n", gen_name->d.uniformResourceIdentifier->data); */
      uri_flag++;
    }
  }

  if (uri_flag == 0) {
#ifdef DEBUG
    fprintf(stderr, "[crldp] no general name of type URI\n");
#endif
    ret = FALSE;
    goto skip;
  } else {
    if (crldp)
      sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    return(TRUE);
  }

skip:
#ifdef DEBUG
  fprintf(stderr, "[crldp] jump to return...\n");
#endif
  if (crldp)
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
  return(ret);
}

/*************************************************************
 * rescert_aia_chk(X509 *, unsigned int)                     *
 *                                                           *
 *  Authority Information Access - non-crit - MUST           *
 *     be present                                            *
 *     in the case of TAs this SHOULD be omitted             *
 *                                                           *
 ************************************************************/
int
rescert_aia_chk(X509 *x, unsigned int cert_type)
{
  int info_flag, uri_flag;
  int i;
  int ex_nid;
  int ret;
  int aia_oid_len;
  AUTHORITY_INFO_ACCESS *aia;
  ACCESS_DESCRIPTION *adesc;
  X509_EXTENSION *ex;
  static const unsigned char aia_oid[] = 
    {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x2};

  aia = NULL;
  adesc = NULL;
  info_flag = uri_flag = 0;
  ret = TRUE;
  aia_oid_len = sizeof(aia_oid);

  if((x->ex_flags & EXFLAG_SET) == 0)
    x509v3_load_extensions(x);
  if ((x->ex_flags & EXFLAG_SET) == 0)
    return(FALSE);

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

    if (ex_nid == NID_info_access) {
      info_flag++;

      if (X509_EXTENSION_get_critical(ex)) {
#ifdef DEBUG
        fprintf(stderr, "[aia] marked critical, violation\n");
#endif
        ret = FALSE;
        goto skip;
      }

    }
  } 
  
  if (info_flag == 0) {
    if (cert_type == TA_CERT) {  /* SHOULD be omitted if TA */
      ret = TRUE; 
      goto skip;
    } else {
#ifdef DEBUG
      fprintf(stderr, "[aia] missing aia extension\n");
#endif
      return(FALSE);
    }
  } else if (info_flag > 1) {
#ifdef DEBUG
    fprintf(stderr, "[aia] multiple aia extensions\n");
#endif
    return(FALSE);
  } 
  
  /* we should be here if NID_info_access was found,
     it was not marked critical, and there was only one instance of it.

     Rob's code from rcynic shows how to get the URI out of the aia...
     so lifting his teachings.  Though he should be using strncasecmp
     rather than strncmp as I don't think there are any specifications
     requiring the URI to be case sensitive.
  */                                  
                                                              
  aia = X509_get_ext_d2i(x, NID_info_access, NULL, NULL);     
  if (!aia) {                                               
#ifdef DEBUG
    fprintf(stderr, "[aia] could not retrieve aia extension\n");        
#endif
    return(FALSE);                                            
  } 
                                                              
  for (i=0; i < sk_ACCESS_DESCRIPTION_num(aia); i++) {
    adesc = sk_ACCESS_DESCRIPTION_value(aia, i);
    if (!adesc) {
#ifdef DEBUG
      fprintf(stderr, "[aia] error retrieving access description\n");
#endif
      ret = FALSE;
      goto skip; 
    }
    /* URI form of object identification in AIA */
    if (adesc->location->type != GEN_URI) {
#ifdef DEBUG
      fprintf(stderr, "[aia] access type of non GEN_URI found\n");
#endif
      ret = FALSE;
      goto skip;
    } 
  
    if ( (adesc->method->length == aia_oid_len) && 
         (!memcmp(adesc->method->data, aia_oid, aia_oid_len)) &&
         (!strncasecmp((const char *)adesc->location->d.uniformResourceIdentifier->data, (const char *)"rsync://", sizeof("rsync://") - 1)) ) {
      uri_flag++;
    } 
  } 

  if (uri_flag == 0) {                                        
#ifdef DEBUG
    fprintf(stderr, "[aia] no aia name of type URI rsync\n"); 
#endif
    ret = FALSE;                                              
    goto skip;                                                
  } else {                                                  
    ret = TRUE;
    goto skip;
  }                                                           
                                                              
skip:                                                         
#ifdef DEBUG
  fprintf(stderr, "[aia] jump to return...\n");             
#endif
  if (aia)                                                  
    sk_ACCESS_DESCRIPTION_pop_free(aia, ACCESS_DESCRIPTION_free);           
  return(ret);                                                
}                                                             



/*************************************************************
 * rescert_sia_chk(X509 *, unsigned int)                     *
 *                                                           *
 *  Subject Information Access -                             *
 *    CA - non-critical - MUST be present                    *
 *    non-CA - MUST NOT be present                           *
 *                                                           *  
 ************************************************************/
int
rescert_sia_chk(X509 *x, unsigned int cert_type)
{
  int sinfo_flag, uri_flag;
  int i;
  int ex_nid;
  int ret;
  int sia_oid_len;
  size_t len;
  AUTHORITY_INFO_ACCESS *sia;
  ACCESS_DESCRIPTION *adesc;
  X509_EXTENSION *ex;
  char c;
  static const unsigned char sia_oid[] =
    {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x5};
    
  sia = NULL;
  adesc = NULL;
  sinfo_flag = uri_flag = 0;
  ret = TRUE; 
  sia_oid_len = sizeof(sia_oid);
  len = 0;
  
  if((x->ex_flags & EXFLAG_SET) == 0)
    x509v3_load_extensions(x);
  if ((x->ex_flags & EXFLAG_SET) == 0)
    return(FALSE); 
    
  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));
    
    if (ex_nid == NID_sinfo_access) {
      sinfo_flag++;                                            
                                                              
      if (X509_EXTENSION_get_critical(ex)) {                  
#ifdef DEBUG
        fprintf(stderr, "[sia] marked critical, violation\n");
#endif
        ret = FALSE;                                          
        goto skip;                                            
      }                                                       

    }                                                         
  }                                                           
                                                              
  if (sinfo_flag == 0) {                                       
    if (cert_type == EE_CERT) {  /* MAY be omitted if not CA */
      ret = TRUE;                                             
      goto skip;                                              
    } else {                                                  
#ifdef DEBUG
      fprintf(stderr, "[sia] missing aia extension\n");       
#endif
      return(FALSE);                                          
    }                                                         
  } else if (sinfo_flag > 1) {                                 
#ifdef DEBUG
    fprintf(stderr, "[sia] multiple aia extensions\n");       
#endif
    return(FALSE);                                            
  }                                                           
                                                              
  /* we should be here if NID_sinfo_access was found,          
     it was not marked critical, and there was only one instance of it.     
                                                              
     Rob's code from rcynic shows how to get the URI out of the aia...      
     so lifting his teachings.  Though he should be using strncasecmp       
     rather than strncmp as I don't think there are any specifications      
     requiring the URI to be case sensitive. Additionally, there were
     no checks in his code to make sure that the RSYNC URI MUST use a
     trailing '/' in the URI.
 
  */                                                          
                                                              
  sia = X509_get_ext_d2i(x, NID_sinfo_access, NULL, NULL);     
  if (!sia) {                                                 
#ifdef DEBUG
    fprintf(stderr, "[sia] could not retrieve aia extension\n");            
#endif
    return(FALSE);                                            
  }                                                           
                                                              
  for (i=0; i < sk_ACCESS_DESCRIPTION_num(sia); i++) {        
    adesc = sk_ACCESS_DESCRIPTION_value(sia, i);              
    if (!adesc) {                                             
#ifdef DEBUG
      fprintf(stderr, "[sia] error retrieving access description\n");       
#endif
      ret = FALSE;                                            
      goto skip;                                              
    }                                                         
    /* URI form of object identification in SIA */
    if (adesc->location->type != GEN_URI) {
#ifdef DEBUG
      fprintf(stderr, "[sia] access type of non GEN_URI found\n");
#endif
      ret = FALSE;
      goto skip;
    } 
    
    if ( (adesc->method->length == sia_oid_len) &&
         (!memcmp(adesc->method->data, sia_oid, sia_oid_len)) &&
         (!strncasecmp((const char *)adesc->location->d.uniformResourceIdentifier->data, (const char *)"rsync://", sizeof("rsync://") - 1)) ) {
      /* it's the right length, right oid, and it _starts_ with
         the correct url method... does it end with a trailing '/'? */
      len = strlen((const char *)adesc->location->d.uniformResourceIdentifier->data);
      /* don't want a wrap case if len comes back 0 */
      if (len == 0) {
        ret = FALSE;
#ifdef DEBUG
        fprintf(stderr, "[sia] ACCESS DESCRIPTOR lengh 0\n");
#endif
        goto skip;
      }
      c = adesc->location->d.uniformResourceIdentifier->data[len - 1];
      if (c == '/')
        uri_flag++;                                             
      else {
#ifdef DEBUG
        fprintf(stderr, "[sia] rsync uri in CA cert without trailing /\n");
#endif
        ret = FALSE;
        goto skip;
      }
    }                                                         
  }                                                           
                                                              
  if (uri_flag == 0) {                                        
#ifdef DEBUG
    fprintf(stderr, "[sia] no sia name of type URI rsync\n"); 
#endif
    ret = FALSE;                                              
    goto skip;                                                
  } else {                                                    
    ret = TRUE;                                               
    goto skip;                                                
  }                                                           
                                                              
skip:                                                         
#ifdef DEBUG
  fprintf(stderr, "[sia] jump to return...\n");               
#endif
  if (sia)                                                    
    sk_ACCESS_DESCRIPTION_pop_free(sia, ACCESS_DESCRIPTION_free);           
  return(ret);                                                
}

/*************************************************************
 * rescert_cert_policy_chk(X509 *, unsigned int)             *
 *                                                           *
 *  Certificate Policies - critical - MUST be present        *
 *    PolicyQualifiers - MUST NOT be used in this profile    *
 *    OID Policy Identifier value: "1.3.6.1.5.5.7.14.2"      *
 *                                                           *                                  
 ************************************************************/
int
rescert_cert_policy_chk(X509 *x, unsigned int cert_type)
{

  int policy_flag;
  int i;
  int ex_nid;
  int ret;
  int len;
  X509_EXTENSION *ex;
  CERTIFICATEPOLICIES *ex_cpols;
  POLICYINFO *policy;
  char policy_id_str[32];
  char *oid_policy_id = "1.3.6.1.5.5.7.14.2\0";
  int policy_id_len = strlen(oid_policy_id);
 
  ex = NULL;
  ex_cpols = NULL;
  policy_flag = 0;
  ret = TRUE;
  
  memset(policy_id_str, '\0', sizeof(policy_id_str));

  if((x->ex_flags & EXFLAG_SET) == 0)
    x509v3_load_extensions(x);
  if ((x->ex_flags & EXFLAG_SET) == 0)
    return(FALSE); 
    
  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));      
                                                              
    if (ex_nid == NID_certificate_policies) {               
      policy_flag++;                                             
      if (!X509_EXTENSION_get_critical(ex)) {                  
#ifdef DEBUG
        fprintf(stderr, "[policy] not marked as critical\n");     
#endif
        ret = FALSE;                                          
        goto skip;                                            
      }                                                       
    }                                                         
  }                                                           
  if (policy_flag == 0) {                                        
#ifdef DEBUG
    fprintf(stderr, "[policy] ski extionsion missing\n");        
#endif
    ret = FALSE;
    goto skip;
  } else if (policy_flag > 1) {                                  
#ifdef DEBUG
    fprintf(stderr, "[policy] multiple instances of ski extension\n");         
#endif
    ret = FALSE;
    goto skip;
  } 

  /* we should be here if policy_flag == 1, it was marked critical,
     and there was only one instance of it. */
  ex_cpols = X509_get_ext_d2i(x, NID_certificate_policies, NULL, NULL); 
  if (!ex_cpols) {
#ifdef DEBUG
    fprintf(stderr, "[policy] policies present but could not retrieve\n");
#endif
    ret = FALSE;
    goto skip;
  }

  if (sk_POLICYINFO_num(ex_cpols) != 1) {
#ifdef DEBUG
    fprintf(stderr, "[policy] incorrect number of policies\n");
#endif
    ret = FALSE;
    goto skip;
  }
   
  policy = sk_POLICYINFO_value(ex_cpols, 0);
  if (!policy) {
#ifdef DEBUG
    fprintf(stderr, "[policy] could not retrieve policyinfo\n");
#endif
    ret = FALSE;
    goto skip;
  }

  if (policy->qualifiers) {
#ifdef DEBUG
    fprintf(stderr, "[policy] must not contain PolicyQualifiers\n");
#endif
    ret = FALSE;
    goto skip;
  }

  len = i2t_ASN1_OBJECT(policy_id_str, sizeof(policy_id_str), policy->policyid);
  
  if ( (len != policy_id_len) || (strcmp(policy_id_str, oid_policy_id)) ) {
#ifdef DEBUG
    fprintf(stderr, "len: %d value: %s\n", len, policy_id_str);
    fprintf(stderr, "[policy] OID Policy Identifier value incorrect\n");
#endif
    ret = FALSE;
    goto skip;
  }
  

skip:                                                         
#ifdef DEBUG
  fprintf(stderr, "[policy] jump to return...\n");
#endif

  if (ex_cpols)                  
    sk_POLICYINFO_pop_free(ex_cpols, POLICYINFO_free);

  return(ret);

}                                                             


/*************************************************************
 * rescert_ip_asnum_chk(X509 *, unsigned int)                *
 *                                                           *
 *  IP Resources, AS Resources - critical - MUST have one    *
 *   of these or both. In the case of one, if present        *
 *   marked as critical                                      *
 *                                                           * 
 * Note that OpenSSL now include Rob's code for 3779         *
 * extensions and it looks like the check and load them      *
 * correctly. All we should need to do is to make sure that  *
 * this function makes sure one or the other (ip or as res)  *
 * is present and then call simple routines to make sure     *
 * there are not multiple instances of the same extension    *
 * and that the extension(s) present are marked critical.    *
 ************************************************************/
int
rescert_ip_asnum_chk(X509 *x, unsigned int cert_type)
{
  int ret;

  if((x->ex_flags & EXFLAG_SET) == 0)                         
    x509v3_load_extensions(x);                                
  if ((x->ex_flags & EXFLAG_SET) == 0)                        
    return(FALSE);                                            

  if ( (x->rfc3779_addr) || (x->rfc3779_asid) ) {
    if (x->rfc3779_addr) {
      ret = rescert_ip_resources_chk(x, cert_type);
      if (ret == FALSE)
        return(FALSE);
    }
    if (x->rfc3779_asid) {
      ret = rescert_as_resources_chk(x, cert_type);
      if (ret == FALSE)
        return(FALSE);
    }
  } else {
    /* doesn't have IP resources OR AS Resources */
    return(FALSE);    
  }

  return(TRUE);
}

/*************************************************************
 * rescert_ip_resources_chk(X509 *, unsigned int)            *
 *                                                           *
 *  IP Resources, AS Resources - critical - MUST have one    *
 *   of these or both. In the case of one, if present        *
 *   marked as critical                                      *
 *                                                           * 
 ************************************************************/
int
rescert_ip_resources_chk(X509 *x, unsigned int cert_type)
{   
  int ipaddr_flag;
  int i;
  int ex_nid;
  int ret;
  X509_EXTENSION *ex;

  ex = NULL;
  ipaddr_flag = 0;
  ret = TRUE;

  if((x->ex_flags & EXFLAG_SET) == 0)
    x509v3_load_extensions(x);
  if ((x->ex_flags & EXFLAG_SET) == 0)
    return(FALSE);

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));

    if (ex_nid == NID_sbgp_ipAddrBlock) {
      ipaddr_flag++;
      if (!X509_EXTENSION_get_critical(ex)) {
#ifdef DEBUG
        fprintf(stderr, "[IP res] not marked as critical\n");
#endif
        return(FALSE);
      }
    }
  }

  if (!ipaddr_flag) {
#ifdef DEBUG
    fprintf(stderr, "[IP res] did not contain IP Resources ext\n");
    fprintf(stderr, "could be ok if AS resources are present and correct\n");
#endif
    return(FALSE);
  } else if (ipaddr_flag > 1) {
#ifdef DEBUG
    fprintf(stderr, "[IP res] multiple instances of IP resources extension\n");
#endif
    return(FALSE);
  }

  return(TRUE);
} 
  
/*************************************************************
 * rescert_as_resources_chk(X509 *, unsigned int)            *
 *                                                           *
 *  IP Resources, AS Resources - critical - MUST have one    *
 *   of these or both. In the case of one, if present        *
 *   marked as critical                                      *
 *                                                           * 
 ************************************************************/
int
rescert_as_resources_chk(X509 *x, unsigned int cert_type)
{
  int asnum_flag;
  int i;
  int ex_nid;
  int ret;
  X509_EXTENSION *ex;                                         
                                                              
  ex = NULL;                                                  
  asnum_flag = 0;                                            
  ret = TRUE;                                                 
                                                              
  if((x->ex_flags & EXFLAG_SET) == 0)                         
    x509v3_load_extensions(x);                                
  if ((x->ex_flags & EXFLAG_SET) == 0)                        
    return(FALSE);                                            
                                                              
  for (i = 0; i < X509_get_ext_count(x); i++) {               
    ex = X509_get_ext(x, i);                                  
    ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));      
                                                              
    if (ex_nid == NID_sbgp_ipAddrBlock) {                     
      asnum_flag++;                                          
      if (!X509_EXTENSION_get_critical(ex)) {                 
#ifdef DEBUG
        fprintf(stderr, "[AS res] not marked as critical\n"); 
#endif
        return(FALSE);                                        
      }                                                       
    }                                                         
  }                                                           
                                                              
  if (!asnum_flag) {                                         
#ifdef DEBUG
    fprintf(stderr, "[AS res] did not contain IP Resources ext\n");
    fprintf(stderr, "could be ok if IP resources are present and correct\n");
#endif
    return(FALSE);                                            
  } else if (asnum_flag > 1) {                                   
#ifdef DEBUG
    fprintf(stderr, "[AS res] multiple instances of AS resources extension\n");
#endif
    return(FALSE);                                            
  }                                                           
                                                              
  return(TRUE);                                               

}

/*************************************************************
 * rescert_criticals_present_chk(X509 *, unsigned int)       *
 *                                                           *
 *  This iterates through what we expect to be critical      *
 *  extensions present in TA,CA,EE certs. If there is a crit *
 *  extension that we don't recognize it fails. If there is  *
 *  an extension that we expect to see as a crit or if an    *
 *  extension that is supposed to be marked crit is marked   *
 *  non-crit it fails.                                       *
 *                                                           * 
 * currently stubbed... don't know if *we* should be doing   *
 * this check or if it should be done elsewhere.
 ************************************************************/
int
rescert_criticals_chk(X509 *x, unsigned int cert_type)
{
  int i;
  X509_EXTENSION *ex;                                         

  ex = NULL;

  if((x->ex_flags & EXFLAG_SET) == 0)
    x509v3_load_extensions(x);
  if ((x->ex_flags & EXFLAG_SET) == 0)
    return(FALSE);

  for (i = 0; i < X509_get_ext_count(x); i++) {
    ex = X509_get_ext(x, i);
    if (!X509_EXTENSION_get_critical(ex))
      continue;
    if (!rescert_crit_ext_chk(ex)) {
      return(FALSE);
    }
  }

  return(TRUE);
}


/*************************************************************
 * This is a minimal modification of                         *
 * x509v3_cache_extensions() found in crypt/X509v3/v3_purp.c *
 * what it does is to load up the X509_st struct so one can  *
 * check extensions in the unsigned long flags within that   *
 * structure rather than recursively calling in the ASN.1    *
 * elements until one finds the correct NID/OID              *
 ************************************************************/
void 
x509v3_load_extensions(X509 *x)
{
  BASIC_CONSTRAINTS *bs;
  PROXY_CERT_INFO_EXTENSION *pci;
  ASN1_BIT_STRING *usage;
  ASN1_BIT_STRING *ns;
  EXTENDED_KEY_USAGE *extusage;
  X509_EXTENSION *ex;

  int i;

  if(x->ex_flags & EXFLAG_SET) 
    return;
#ifndef OPENSSL_NO_SHA
  X509_digest(x, EVP_sha1(), x->sha1_hash, NULL);
#endif
  /* Does subject name match issuer ? */
  if(!X509_NAME_cmp(X509_get_subject_name(x), X509_get_issuer_name(x)))
    x->ex_flags |= EXFLAG_SS;
  /* V1 should mean no extensions ... */
  if(!X509_get_version(x)) 
    x->ex_flags |= EXFLAG_V1;
  /* Handle basic constraints */
  if((bs=X509_get_ext_d2i(x, NID_basic_constraints, NULL, NULL))) {
    if(bs->ca) 
      x->ex_flags |= EXFLAG_CA;
    if(bs->pathlen) {
      if((bs->pathlen->type == V_ASN1_NEG_INTEGER) || !bs->ca) {
        x->ex_flags |= EXFLAG_INVALID;
        x->ex_pathlen = 0;
      } else {
        x->ex_pathlen = ASN1_INTEGER_get(bs->pathlen);
      }
    } else {
      x->ex_pathlen = -1; 
    }

    BASIC_CONSTRAINTS_free(bs);
    x->ex_flags |= EXFLAG_BCONS; 
  } 

  /* Handle proxy certificates */ 
  if((pci=X509_get_ext_d2i(x, NID_proxyCertInfo, NULL, NULL))) {
    if (x->ex_flags & EXFLAG_CA || 
        X509_get_ext_by_NID(x, NID_subject_alt_name, 0) >= 0
        || X509_get_ext_by_NID(x, NID_issuer_alt_name, 0) >= 0) { 
      x->ex_flags |= EXFLAG_INVALID;
    }
    if (pci->pcPathLengthConstraint) {
      x->ex_pcpathlen = ASN1_INTEGER_get(pci->pcPathLengthConstraint);
    } else {
      x->ex_pcpathlen = -1;
    }
    PROXY_CERT_INFO_EXTENSION_free(pci);
    x->ex_flags |= EXFLAG_PROXY;
  }

  /* Handle key usage */
  if((usage=X509_get_ext_d2i(x, NID_key_usage, NULL, NULL))) {
    if(usage->length > 0) {
      x->ex_kusage = usage->data[0];
      if(usage->length > 1)
        x->ex_kusage |= usage->data[1] << 8;
    } else {
      x->ex_kusage = 0;
    }
    x->ex_flags |= EXFLAG_KUSAGE;
    ASN1_BIT_STRING_free(usage);
  }
  x->ex_xkusage = 0;
  if((extusage=X509_get_ext_d2i(x, NID_ext_key_usage, NULL, NULL))) {
    x->ex_flags |= EXFLAG_XKUSAGE;
    for(i = 0; i < sk_ASN1_OBJECT_num(extusage); i++) {
      switch(OBJ_obj2nid(sk_ASN1_OBJECT_value(extusage,i))) {
        case NID_server_auth:
          x->ex_xkusage |= XKU_SSL_SERVER;
          break;

        case NID_client_auth:
          x->ex_xkusage |= XKU_SSL_CLIENT;
          break;

        case NID_email_protect:
          x->ex_xkusage |= XKU_SMIME;
          break;

        case NID_code_sign:
          x->ex_xkusage |= XKU_CODE_SIGN;
          break;

        case NID_ms_sgc:
        case NID_ns_sgc:
          x->ex_xkusage |= XKU_SGC;
          break;

        case NID_OCSP_sign:
          x->ex_xkusage |= XKU_OCSP_SIGN;
          break;

        case NID_time_stamp:
          x->ex_xkusage |= XKU_TIMESTAMP;
          break;

        case NID_dvcs:
          x->ex_xkusage |= XKU_DVCS;
          break;
      }
    }
    sk_ASN1_OBJECT_pop_free(extusage, ASN1_OBJECT_free);
  }

  if((ns=X509_get_ext_d2i(x, NID_netscape_cert_type, NULL, NULL))) {  
    if(ns->length > 0) x->ex_nscert = ns->data[0];
    else x->ex_nscert = 0;                        
    x->ex_flags |= EXFLAG_NSCERT;                 
    ASN1_BIT_STRING_free(ns);                     
  }                                                     

  x->skid =X509_get_ext_d2i(x, NID_subject_key_identifier, NULL, NULL);
  x->akid =X509_get_ext_d2i(x, NID_authority_key_identifier, NULL, NULL);
#ifdef OUT
   /* the crldp element didn't show up in the x509_st until after
      OpenSSL 0.9.8e-dev XX xxx XXXX apparently  */
  /* NOTE */
  /* we check for it manually in the rescert_crldp_chk() function */
  x->crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
#endif
#ifndef OPENSSL_NO_RFC3779                                    
  x->rfc3779_addr =X509_get_ext_d2i(x, NID_sbgp_ipAddrBlock, NULL, NULL);
  x->rfc3779_asid =X509_get_ext_d2i(x, NID_sbgp_autonomousSysNum, NULL, NULL);
#endif                                                        

  for (i = 0; i < X509_get_ext_count(x); i++) { 
    ex = X509_get_ext(x, i);                      
    if (!X509_EXTENSION_get_critical(ex))         
      continue;                             
    if (!X509_supported_extension(ex)) {                                     
      x->ex_flags |= EXFLAG_CRITICAL;       
      break;                                
    }                                     
  }                                             
  x->ex_flags |= EXFLAG_SET;                            
}                                                             

int 
rescert_crit_ext_chk(X509_EXTENSION *ex)
{
  /* this function is a minimal change to OpenSSL's 
     X509_supported_extension() function from
     crypto/x509v3/v3_purp.c 

     The modifications are a change in the supported nids
     array to match the Resource Certificate Profile sepecification 

     This function is used to catch extensions that
     might be marked critical that we were not expecting. You should
     only pass this criticals.

     Criticals in Resource Certificate Profile:
       Basic Constraints
       Key Usage
       Certificate Policies
        (NOT Subject Alt Name, which is going to be removed
         anyway in the future from this profile)
       IP Resources
       AS Resources
  */       

  /* This table is a list of the NIDs of supported extensions:
   * that is those which are used by the verify process. If
   * an extension is critical and doesn't appear in this list
   * then the verify process will normally reject the certificate.
   * The list must be kept in numerical order because it will be
   * searched using bsearch.
   */

       
  static int supported_nids[] = {
            NID_key_usage,          /* 83 */
            NID_basic_constraints,  /* 87 */
            NID_certificate_policies, /* 89 */
            NID_sbgp_ipAddrBlock,   /* 290 */
            NID_sbgp_autonomousSysNum, /* 291 */
  };                                                    
                                                              
  int ex_nid;                                           
                                                              
  ex_nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));  
                                                              
  if (ex_nid == NID_undef)                              
    return FALSE;                                     
                                                              
  if (OBJ_bsearch((char *)&ex_nid, (char *)supported_nids,
                  sizeof(supported_nids)/sizeof(int), sizeof(int),
                  (int (*)(const void *, const void *))res_nid_cmp))
    return(TRUE);                                     
  return(FALSE); 
}                                                     

/* from x509v3/v3_purp.c */
static int 
res_nid_cmp(int *a, int *b)
{
  return *a - *b;
}

void
debug_chk_printf(char *str, int val, int cert_type)
{
  char *ta_cert_str = "TA_CERT";
  char *ca_cert_str = "CA_CERT";
  char *ee_cert_str = "EE_CERT";
  char *unk_cert_str = "UNK_CERT";
  char *cert_str;
  char *true_str = "TRUE";
  char *false_str = "FALSE";
  char *val_str;
  char other_val_str[32];
  char other_cert_str[32];

  cert_str = val_str = NULL;
  memset(other_cert_str, '\0', sizeof(other_cert_str));
  memset(other_val_str, '\0', sizeof(other_val_str));

  switch(cert_type) {
    case CA_CERT:
      cert_str = ca_cert_str;
      break;
    case TA_CERT:
      cert_str = ta_cert_str;
      break;
    case EE_CERT:
      cert_str = ee_cert_str;
      break;
    case UNK_CERT:
      cert_str = unk_cert_str;
      break;
    default:
      snprintf(other_cert_str, sizeof(other_cert_str) - 1, 
               "cert type val: %d (\?\?)", cert_type);
      cert_str = other_cert_str;
      break;
  }
  
  switch(val) {
    case TRUE:
      val_str = true_str;
      break;
    case FALSE:
      val_str = false_str;
      break;
    default:
      snprintf(other_val_str, sizeof(other_val_str) - 1,
               "%d (\?\?)", val);
      val_str = other_val_str;
      break;
  }

  fprintf(stderr, "%s returned: %s [against: %s]\n", str, val_str, cert_str);

}
