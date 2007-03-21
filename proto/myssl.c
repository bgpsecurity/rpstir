/*
  $Id$
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <getopt.h>
#include <time.h>

#include "myssl.h"
#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "err.h"

#ifdef NOTDEF

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

#endif

/*
  Convert between a time string as defined by a GENERALIZED_TIME
  and a time string that will be acceptable to the DB. The return
  value is allocated memory.

  The GENERALIZED_TIME is in the form YYMMDDHHMMSST, where each of
  the fields is as follows:
      if YY <= 36 the year is 2000+YY otherwise it is 1900+YY
      1 <= MM <= 12
      1 <= DD <= 31
      0 <= HH <= 24
      0 <= MM <= 60
      0 <= SS <= 60
      T, is present and == Z indicates GMT
*/

char *ASNTimeToDBTime(char *bef, int *stap)
{
  int   year;
  int   mon;
  int   day;
  int   hour;
  int   min;
  int   sec;
  int   cnt;
  char  tz = 0;
  char *out;

  if ( stap == NULL )
    return(NULL);
  *stap = 0;
  if ( bef == NULL || bef[0] == 0 )
    {
      *stap = ERR_SCM_INVALARG;
      return(NULL);
    }
  cnt = sscanf(bef, "%2d%2d%2d%2d%2d%2d%c", &year, &mon, &day,
	       &hour, &min, &sec, &tz);
  if ( cnt != 7 )
    {
      *stap = ERR_SCM_INVALDT;
      return(NULL);
    }
  if ( tz != 'Z' || mon < 1 || mon > 12 || day < 1 || day > 31 || hour < 0 ||
       hour > 23 || min < 0 || min > 59 || sec < 0 || sec > 61 )
    /* 61 because of leap seconds */
    {
      *stap = ERR_SCM_INVALDT;
      return(NULL);
    }
  if ( year > 36 )
    year += 1900;
  else
    year += 2000;
  out = (char *)calloc(24, sizeof(char));
  if ( out == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  (void)sprintf(out, "%4d-%2d-%2d %2d:%2d:%2d", year, mon, day, hour, min, sec);
  return(out);
}

void freecf(cert_fields *cf)
{
  int i;

  if ( cf == NULL )
    return;
  for(i=0;i<CF_NFIELDS;i++)
    {
      if ( cf->fields[i] != NULL )
	{
	  free((void *)(cf->fields[i]));
	  cf->fields[i] = 0;
	}
    }
  free((void *)cf);
}

static char *cf_get_subject(X509 *x, int *stap, int *x509stap)
{
  char *ptr;
  char *dptr;

  if ( x == NULL || stap == NULL || x509stap == NULL )
    return(NULL);
  ptr = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);
  if ( ptr == NULL )
    {
      *stap = ERR_SCM_NOSUBJECT;
      return(NULL);
    }
  dptr = strdup(ptr);
  if ( dptr == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  return(dptr);
}

static char *cf_get_issuer(X509 *x, int *stap, int *x509stap)
{
  char *ptr;
  char *dptr;

  if ( x == NULL || stap == NULL || x509stap == NULL )
    return(NULL);
  ptr = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);
  if ( ptr == NULL )
    {
      *stap = ERR_SCM_NOISSUER;
      return(NULL);
    }
  dptr = strdup(ptr);
  if ( dptr == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  return(dptr);
}

static char *cf_get_sn(X509 *x, int *stap, int *x509stap)
{
  ASN1_INTEGER *a1;
  BIGNUM *bn;
  char   *ptr;
  char   *dptr;

  if ( x == NULL || stap == NULL || x509stap == NULL )
    return(NULL);
  a1 = X509_get_serialNumber(x);
  if ( a1 == NULL )
    {
      *stap = ERR_SCM_NOSN;
      return(NULL);
    }
  bn = ASN1_INTEGER_to_BN(a1, NULL);
  if ( bn == NULL )
    {
      *stap = ERR_SCM_BIGNUMERR;
      return(NULL);
    }
  ptr = BN_bn2dec(bn);
  if ( ptr == NULL )
    {
      BN_free(bn);
      *stap = ERR_SCM_BIGNUMERR;
      return(NULL);
    }
  dptr = strdup(ptr);
  OPENSSL_free(ptr);
  BN_free(bn);
  if ( dptr == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  return(dptr);
}

static char *cf_get_from(X509 *x, int *stap, int *x509stap)
{
  ASN1_GENERALIZEDTIME *nb4;
  unsigned char *bef = NULL;
  char *dptr;
  int   asn1sta;

  nb4 = X509_get_notBefore(x);
  if ( nb4 == NULL )
    {
      *stap = ERR_SCM_NONB4;
      return(NULL);
    }
  asn1sta = ASN1_STRING_to_UTF8(&bef, (ASN1_STRING *)nb4);
  if ( asn1sta < 0 )		/* error */
    {
      *x509stap = asn1sta;
      *stap = ERR_SCM_X509;
      return(NULL);
    }
  if ( bef == NULL || asn1sta == 0 ) /* null string */
    {
      *stap = ERR_SCM_NONB4;
      return(NULL);
    }
  dptr = ASNTimeToDBTime((char *)bef, stap);
  OPENSSL_free(bef);
  if ( dptr == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  return(dptr);
}

static char *cf_get_to(X509 *x, int *stap, int *x509stap)
{
  ASN1_GENERALIZEDTIME *naf;
  unsigned char *aft = NULL;
  char *dptr;
  int   asn1sta;

  naf = X509_get_notAfter(x);
  if ( naf == NULL )
    {
      *stap = ERR_SCM_NONAF;
      return(NULL);
    }
  asn1sta = ASN1_STRING_to_UTF8(&aft, (ASN1_STRING *)naf);
  if ( asn1sta < 0 )		/* error */
    {
      *x509stap = asn1sta;
      *stap = ERR_SCM_X509;
      return(NULL);
    }
  if ( aft == NULL || asn1sta == 0 ) /* null string */
    {
      *stap = ERR_SCM_NONAF;
      return(NULL);
    }
  dptr = ASNTimeToDBTime((char *)aft, stap);
  OPENSSL_free(aft);
  if ( dptr == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  return(dptr);
}

static void cf_get_ski(X509V3_EXT_METHOD *meth, void *exts,
		       cert_fields *cf, int *stap, int *x509stap)
{
  char *ptr;
  char *dptr;

  if ( stap == NULL )
    return;
  if ( meth == NULL || exts == NULL || cf == NULL || x509stap == NULL )
    {
      *stap = ERR_SCM_INVALARG;
      return;
    }
  if ( meth->i2s == NULL )
    {
      *stap = ERR_SCM_BADEXT;
      return;
    }
  ptr = meth->i2s(meth, exts);
  if ( ptr == NULL || ptr[0] == 0 )
    {
      *stap = ERR_SCM_BADEXT;
      return;
    }
  dptr = strdup(ptr);
  OPENSSL_free(ptr);
  if ( dptr == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return;
    }
  cf->fields[CF_FIELD_SKI] = dptr;
}

static void cf_get_aki(X509V3_EXT_METHOD *meth, void *exts,
		       cert_fields *cf, int *stap, int *x509stap)
{
  AUTHORITY_KEYID *aki;
  char *ptr;
  char *dptr;

  if ( stap == NULL )
    return;
  if ( meth == NULL || exts == NULL || cf == NULL || x509stap == NULL )
    {
      *stap = ERR_SCM_INVALARG;
      return;
    }
  aki = (AUTHORITY_KEYID *)exts;
  if ( aki->keyid == NULL )
    {
      *stap = ERR_SCM_XPROFILE;
      return;
    }
  ptr = hex_to_string(aki->keyid->data, aki->keyid->length);
  if ( ptr == NULL )
    {
      *stap = ERR_SCM_INVALEXT;
      return;
    }
  dptr = strdup(ptr);
  OPENSSL_free(ptr);
  if ( dptr == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return;
    }
  cf->fields[CF_FIELD_AKI] = dptr;
}

static void cf_get_sia(X509V3_EXT_METHOD *meth, void *exts,
		       cert_fields *cf, int *stap, int *x509stap)
{
  // GAGNON
}

static void cf_get_aia(X509V3_EXT_METHOD *meth, void *exts,
		       cert_fields *cf, int *stap, int *x509stap)
{
  // GAGNON
}

static void cf_get_crldp(X509V3_EXT_METHOD *meth, void *exts,
			 cert_fields *cf, int *stap, int *x509stap)
{
  STACK_OF(DIST_POINT) *crld;
  char *ptr;
  char *dptr;

  if ( stap == NULL )
    return;
  if ( meth == NULL || exts == NULL || cf == NULL || x509stap == NULL )
    {
      *stap = ERR_SCM_INVALARG;
      return;
    }
  // GAGNON
}

static void cf_get_flags(X509V3_EXT_METHOD *meth, void *exts,
			 cert_fields *cf, int *stap, int *x509stap)
{
  BASIC_CONSTRAINTS *bk;
  unsigned int flags = 0;
  char *ptr;
  char *cff;
  int   isca;

  UNREFERENCED_PARAMETER(meth);
  if ( stap == NULL )
    return;
  if ( exts == NULL || cf == NULL || x509stap == NULL )
    {
      *stap = ERR_SCM_INVALARG;
      return;
    }
  bk = (BASIC_CONSTRAINTS *)exts;
  isca = bk->ca;
  if ( isca != 0 )
    {
      ptr = (char *)calloc(24, sizeof(char));
      if ( ptr == NULL )
	{
	  *stap = ERR_SCM_NOMEM;
	  return;
	}
      if ( (cff=cf->fields[CF_FIELD_FLAGS]) != NULL )
	flags = atoi(cff);
      flags |= SCM_FLAG_CA;
      (void)sprintf(ptr, "%d", flags);
      if ( cff != NULL )
	free((void *)cff);
      cf->fields[CF_FIELD_FLAGS] = ptr;
    }
}

static cfx_validator xvalidators[] = 
  {
    { cf_get_ski,     CF_FIELD_SKI,     NID_subject_key_identifier,   1 } ,
    { cf_get_aki,     CF_FIELD_AKI,     NID_authority_key_identifier, 1 } ,
    { cf_get_sia,     CF_FIELD_SIA,     NID_sinfo_access,             0 } ,
    { cf_get_aia,     CF_FIELD_AIA,     NID_info_access,              0 } ,
    { cf_get_crldp,   CF_FIELD_CRLDP,   NID_crl_distribution_points,  0 } ,
    { cf_get_flags,   CF_FIELD_FLAGS,   NID_basic_constraints,        1 }
  } ;

/*
  Given an X509V3 extension tag, this function returns the corresponding
  extension validator.
*/

static cfx_validator *cfx_find(int tag)
{
  unsigned int i;

  for(i=0;i<sizeof(xvalidators)/sizeof(cfx_validator);i++)
    {
      if ( xvalidators[i].tag == tag )
	return(&xvalidators[i]);
    }
  return(NULL);
}

static cf_validator validators[] = 
{ 
  { cf_get_subject, CF_FIELD_SUBJECT, 1 } ,
  { cf_get_issuer,  CF_FIELD_ISSUER,  1 } ,
  { cf_get_sn,      CF_FIELD_SN,      1 } ,
  { cf_get_from,    CF_FIELD_FROM,    1 } ,
  { cf_get_to,      CF_FIELD_TO,      1 }
} ;

/*
  This function opens a certificate from a file and extracts all the fields
  from it.  It does not touch the DB at all, it just manipulates the certificate.

  On success this function returns a pointer to allocated memory containing
  all the indicated fields (except the three integer fields) and sets stap to 0,
  and x509stap to 1.

  Note carefully that this function does NOT set all the fields in the cf.
  In particular, it is the responsibility of the caller to set the dirid
  and myid fields.  These two fields require DB access and are therefore
  not part of this function.

  On failure this function returns NULL and sets stap to a non-negative error
  code. If an X509 error occurred, x509stap is set to that error.
*/

cert_fields *cert2fields(char *fname, char *fullname, int typ, int *stap, int *x509stap)
{
  const unsigned char *udat;
  cfx_validator       *cfx;
  X509V3_EXT_METHOD   *meth;
  X509_EXTENSION      *ex;
  X509_CINF   *ci;
  cert_fields *cf;
  BIO  *bcert;
  X509 *x;
  void *exts;
  char *res;
  int   x509sta;
  int   excnt;
  int   i;

  if ( stap == NULL || x509stap == NULL )
    return(NULL);
  *x509stap = 1;
  if ( fname == NULL || fname[0] == 0 || fullname == NULL || fullname[0] == 0 )
    {
      *stap = ERR_SCM_INVALARG;
      return(NULL);
    }
  cf = (cert_fields *)calloc(1, sizeof(cert_fields));
  if ( cf == NULL )
    {
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  cf->fields[CF_FIELD_FILENAME] = strdup(fname);
  if ( cf->fields[CF_FIELD_FILENAME] == NULL )
    {
      freecf(cf);
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
// open the file
  bcert = BIO_new(BIO_s_file());
  if ( bcert == NULL )
    {
      freecf(cf);
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  x509sta = BIO_read_filename(bcert, fullname);
  if ( x509sta <= 0 )
    {
      BIO_free_all(bcert);
      freecf(cf);
      *stap = ERR_SCM_X509;
      *x509stap = x509sta;
      return(NULL);
    }
// read the cert based on the input type
  if ( typ < OT_PEM_OFFSET )
    x = d2i_X509_bio(bcert, NULL);
  else
    x = PEM_read_bio_X509_AUX(bcert, NULL, NULL, NULL);
  if ( x == NULL )
    {
      BIO_free_all(bcert);
      freecf(cf);
      *stap = ERR_SCM_BADCERT;
      return(NULL);
    }
// get all the non-extension fields; if a field cannot be gotten and its critical,
// that is a fatal error
  for(i=1;i<CF_NFIELDS;i++)
    {
      res = (*validators[i].get_func)(x, stap, x509stap);
      if ( res == NULL && validators[i].critical > 0 )
	{
	  X509_free(x);
	  BIO_free_all(bcert);
	  freecf(cf);
	  if ( *stap == 0 )
	    *stap = ERR_SCM_X509;
	  return(NULL);
	}
      cf->fields[i] = res;
    }
// get the extension fields
  excnt = X509_get_ext_count(x);
  ci = x->cert_info;
  for(i=0;i<excnt;i++)
    {
      ex = sk_X509_EXTENSION_value(ci->extensions, i);
      if ( ex == NULL )
	continue;
      meth = X509V3_EXT_get(ex);
      if ( meth == NULL )
	continue;
      udat = ex->value->data;
      if ( meth->it )
	exts = ASN1_item_d2i(NULL, &udat, ex->value->length,
			     ASN1_ITEM_ptr(meth->it));
      else
	exts = meth->d2i(NULL, &udat, ex->value->length);
      if ( exts == NULL )
	continue;
      cfx = cfx_find(meth->ext_nid);
      if ( cfx == NULL || cfx->get_func == NULL )
	continue;
      *stap = 0;
      *x509stap = 0;
      (*cfx->get_func)(meth, exts, cf, stap, x509stap);
      if ( *stap != 0 && cfx->critical != 0 )
	break;
    }
// check that all critical extension fields are present
  for(ui=0;ui<sizeof(xvalidator)/sizeof(cfx_validator);ui++)
    {
      if ( xvalidator[ui].critical != 0 && cf->fields[xvalidator[ui].fieldno] == NULL )
	{
	  *stap = ERR_SCM_MISSEXT;
	  break;
	}
    }
  X509_free(x);
  BIO_free_all(bcert);
  if ( *stap != 0 )
    {
      freecf(cf);
      cf = NULL;
    }
  return(cf);
}
