/*
  $Id$
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#include <openssl/bn.h>

// print one extension

static void printex(X509_EXTENSION *ex)
{
  X509V3_EXT_METHOD    *meth;
  AUTHORITY_KEYID      *aki;
  BASIC_CONSTRAINTS    *bk;
  STACK_OF(DIST_POINT) *crld;
  const unsigned char  *uleon;
  GENERAL_NAMES *gen;
  GENERAL_NAME  *gen1;
  DIST_POINT    *point;
  void *exts;
  char *leon;
  int   j;
  int   k;

  meth = X509V3_EXT_get(ex);
  //      (void)printf("\tMethod pointer 0x%x\n", meth);
  if ( meth == NULL )
    return;
  uleon = ex->value->data;
  if ( meth->it )
    exts = ASN1_item_d2i(NULL, &uleon, ex->value->length,
			 ASN1_ITEM_ptr(meth->it));
  else
    exts = meth->d2i(NULL, &uleon, ex->value->length);
  //      (void)printf("\tExtension data pointer 0x%x\n", exts);
  if ( exts == NULL )
    return;
  switch ( meth->ext_nid )
    {
    case NID_basic_constraints:
      bk = (BASIC_CONSTRAINTS *)exts;
      if ( bk->ca == 0 )
	(void)printf("\t\tCA: FALSE\n");
      else
	(void)printf("\t\tCA: TRUE\n");
      break;
    case NID_subject_key_identifier:
      if ( meth->i2s != NULL )
	{
	  leon = meth->i2s(meth, exts);
	  if ( leon != NULL )
	    {
	      (void)printf("\t\t%s\n", leon);
	      OPENSSL_free(leon);
	    }
	}
      break;
    case NID_authority_key_identifier:
      aki = (AUTHORITY_KEYID *)exts;
      if ( aki->keyid != NULL )
	{
	  leon = hex_to_string(aki->keyid->data, aki->keyid->length);
	  if ( leon != NULL )
	    {
	      (void)printf("\t\t%s\n", leon);
	      OPENSSL_free(leon);
	    }
	}
      else
	{
	  (void)printf("Certificate with AKI=ISSUER/SNO\n");
	  (void)printf("This is PROHIBITED by the profile\n");
	}
      break;
    case NID_crl_distribution_points:
      crld = (STACK_OF(DIST_POINT) *)exts;
      for(j=0;j<sk_DIST_POINT_num(crld);j++)
	{
	  point = sk_DIST_POINT_value(crld, j);
	  if ( point->distpoint != NULL )
	    {
//	      (void)printf("\t\tCRLDP(%d):\n", j+1);
	      gen = point->distpoint->name.fullname;
	      for(k=0;k<sk_GENERAL_NAME_num(gen);k++)
		{
		  gen1 = sk_GENERAL_NAME_value(gen, k);
// TODO: must handle wider set of cases here, incl DIRNAME
		  (void)printf("\t\t%s\n", gen1->d.ia5->data);
		}
	    }
	}
      break;
// TODO: SIA and AIA
    default:
      break;
    }
  if ( meth->it )
    ASN1_item_free(exts, ASN1_ITEM_ptr(meth->it));
  else
    meth->ext_free(exts);
}

// cycle through all filenames on the command line and process them
// as certs

int main(int argc, char **argv)
{
  X509_EXTENSION *ex;
  ASN1_INTEGER   *a1;
  ASN1_OBJECT    *ao;
  ASN1_GENERALIZEDTIME *nb4;
  ASN1_GENERALIZEDTIME *af4;
  unsigned long   ell;
  X509_CINF      *ci;
  BIGNUM *bn;
  BIO    *cert;
  X509   *x = NULL;
  char   *leon;
  unsigned char *bef;
  unsigned char *aft;
  char    buf[256];
  int     sta;
  int     excnt;
  int     i;
  int     j;

  if ( argc < 2 )
    return(1);
  (void)setbuf(stdout, NULL);
  cert = BIO_new(BIO_s_file());
  // (void)printf("BIO pointer is 0x%x\n", cert);
  if ( cert == NULL )
    return(-1);
  for(j=1;j<argc;j++)
    {
      sta = BIO_read_filename(cert, argv[j]);
      (void)printf("Status reading %s: %d\n", argv[j], sta);
      if ( sta <= 0 )
	continue;
      x = d2i_X509_bio(cert, NULL);
      //      (void)printf("X509 pointer is 0x%x\n", x);
      if ( x == NULL )
	continue;
      leon = X509_NAME_oneline(X509_get_issuer_name(x), NULL, 0);
      (void)printf("Issuer: %s\n", leon);
      leon = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);
      (void)printf("Subject: %s\n", leon);
      a1 = X509_get_serialNumber(x);
      bn = ASN1_INTEGER_to_BN(a1, NULL);
      if ( bn == NULL )
	{
	  X509_free(x);
	  continue;
	}
      leon = BN_bn2dec(bn);
      (void)printf("Serial number: %s\n", leon);
      BN_free(bn);
      nb4 = X509_get_notBefore(x);
      af4 = X509_get_notAfter(x);
      ASN1_STRING_to_UTF8(&bef, (ASN1_STRING *)nb4);
      ASN1_STRING_to_UTF8(&aft, (ASN1_STRING *)af4);
      (void)printf("Validity from %s to %s\n", bef, aft);
      ell = X509_subject_name_hash(x);
      (void)printf("Subject name hash: 0x%x\n", ell);
      (void)printf("Number of extensions: %d\n",
		   excnt=X509_get_ext_count(x));
      ci = x->cert_info;
      //      (void)printf("Certificate info pointer is 0x%x\n", ci);
      //      (void)printf("Extensions pointer is 0x%x\n", ci->extensions);
      for(i=0;i<excnt;i++)
	{
	  ex = sk_X509_EXTENSION_value(ci->extensions, i);
      // (void)printf("\tExtension %d: 0x%x\n", i+1, ex);
	  ao = X509_EXTENSION_get_object(ex);
	  memset(buf, 0, 256);
	  sta = OBJ_obj2txt(buf, 256, ao, 0);
	  if ( sta > 0 && buf[0] != 0 )
	    {
	      (void)printf("\tExtension %d: %s\n", i+1, buf);
//	      if ( strstr(buf, "Key Identifier") != NULL )
		printex(ex);
	    }
	}
      X509_free(x);
    }
  return(0);
}
